#![allow(non_snake_case)]
use std::{collections::{hash_map::DefaultHasher}, string::FromUtf16Error, fs::File, io::Read, hash::{Hash, Hasher}, os::windows::prelude::FileExt};
use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};
use xorf::prelude::bfuse::hash_of_hash;
use windows_sys::Win32::Foundation::*;
use sha1::{Sha1, Digest};
use log::{error, info};
use zeroize::Zeroize;
use core::slice;


/// Consumes the given `UNICODE_STRING` buffer, zeroizing it and
/// returning a Rust `String` in the process.
unsafe fn string_from_windows(unicode_string: *mut UNICODE_STRING) -> Result<String, FromUtf16Error> {
    let buffer = unsafe { slice::from_raw_parts_mut((*unicode_string).Buffer, ((*unicode_string).Length / 2) as usize) };
    let res = String::from_utf16(buffer);
    buffer.zeroize();

    res
}

/// Initializes the Event Log provider on first load.
pub extern "system" fn InitializeChangeNotify() -> BOOLEAN {
    match winlog::init("Sediment") {
        Ok(_) => {},
        Err(_) => return false.into()
    }

    info!("Successfully loaded password filter.");
    true.into()
}

/// Logs if a user password was successfully changed.
/// 
/// ## Safety
/// Called by Windows whenever a user successfully changes
/// or sets their password.
pub unsafe extern "system" fn PasswordChangeNotify(
    username: *mut UNICODE_STRING,
    _relative_id: u32,
    new_password: *mut UNICODE_STRING
) -> NTSTATUS {
    if (*new_password).Length > 1 {
        let buffer = unsafe { slice::from_raw_parts_mut((*new_password).Buffer, ((*new_password).Length / 2) as usize) };
        buffer.zeroize();
    }

    let username = match string_from_windows(username) {
        Ok(username) => username,
        Err(err) => {
            error!("Failed to read username:\n{err:?}");
            return STATUS_SUCCESS
        }
    };

    info!("{username} successfully set their password");

    STATUS_SUCCESS
}

/// Receives the user's plaintext password and checks against
/// the compromised and banned word stores to see if it is
/// allowed.
/// 
/// ## Safety
/// Called by Windows whenever a user attempts to change
/// or set their password.
pub unsafe extern "system" fn PasswordFilter(
    _account_name: *mut UNICODE_STRING,
    _full_name: *mut UNICODE_STRING,
    password: *mut UNICODE_STRING,
    _set_operation: BOOLEAN
) -> BOOLEAN {
    if (*password).Length <= 1 {
        error!("Password was empty");
        return false.into()
    }
    
    let mut password = match string_from_windows(password) {
        Ok(password) => password,
        Err(_) => {
            error!("Failed to parse password");
            return false.into()
        }
    };
    
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let mut password_hashed = format!("{hash:X}");
    password.zeroize();

    let mut hasher = DefaultHasher::new();
    password_hashed.hash(&mut hasher);
    let key = hasher.finish();
    
    let filter_path: String = {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let app_key = match hklm.create_subkey("SOFTWARE\\sediment") {
            Ok(key) => key,
            Err(err) => {
                error!("Cannot open registry key:\n{err:?}");
                return false.into()
            }
        };

        match app_key.get_value("FilterPath") {
            Ok(path) => path,
            Err(err) => {
                error!("Could not find 'FilterPath' key:\n{err:?}");
                return false.into()
            }
        }
    };

    let mut filter_file = match File::open(format!("{filter_path}\\{}", &password_hashed[..2])) {
        Ok(filter_file) => filter_file,
        Err(err) => {
            error!("Failed to open filter file:\n{err:?}");
            return false.into()
        }
    };
    password_hashed.zeroize();

    let mut buffer = [0; 8];
    filter_file.read_exact(&mut buffer).unwrap();
    let seed = u64::from_le_bytes(buffer);

    let mut buffer = [0; 4];
    filter_file.read_exact(&mut buffer).unwrap();
    let segment_length = u32::from_le_bytes(buffer);

    buffer.fill(0);
    filter_file.read_exact(&mut buffer).unwrap();
    let segment_length_mask = u32::from_le_bytes(buffer);

    buffer.fill(0);
    filter_file.read_exact(&mut buffer).unwrap();
    let segment_count_length = u32::from_le_bytes(buffer);

    let hash = xorf::prelude::mix(key, seed);
    let mut fprint = xorf::fingerprint!(hash) as u8;
    let (h0, h1, h2) = hash_of_hash(hash, segment_length, segment_length_mask, segment_count_length);

    let mut buffer = [0; 1];
    filter_file.seek_read(&mut buffer, (20 + h0) as u64).unwrap();
    let h0 = buffer[0];
    
    filter_file.seek_read(&mut buffer, (20 + h1) as u64).unwrap();
    let h1 = buffer[0];

    filter_file.seek_read(&mut buffer, (20 + h2) as u64).unwrap();
    let h2 = buffer[0];

    fprint ^= h0 ^ h1 ^ h2;

    (fprint != 0).into()
}


#[cfg(test)]
mod tests {
    use windows_sys::Win32::Foundation::*;
    use std::ptr::null_mut;

    use super::PasswordFilter;

    macro_rules! create_unicode {
        ( $data:expr ) => {
            {
                let mut data = String::from($data)
                                            .encode_utf16()
                                            .collect::<Vec<u16>>();

                UNICODE_STRING {
                    Length: (data.len() * 2) as u16,
                    MaximumLength: (data.capacity() * 2) as u16,
                    Buffer: data.as_mut_ptr()
                }
            }
        }
    }

    #[test]
    fn InitializeChangeNotify() {
        assert!(super::InitializeChangeNotify() > 0);
    }

    #[test]
    fn PasswordChangeNotify() {
        let mut username = create_unicode!("ChangeNotifyTester");
        let mut password = create_unicode!("");

        assert_eq!(unsafe{ super::PasswordChangeNotify(&mut username, 0, &mut password) }, 0);
    }
    
    #[test]
    fn PasswordFilter_goodpassword() {
        let mut password = create_unicode!("RustySediments");
        
        let true_bool: BOOLEAN = true.into();
        assert_eq!(unsafe{ PasswordFilter(null_mut(), null_mut(), &mut password, 0) }, true_bool);
    }

    #[test]
    fn PasswordFilter_badpassword() {
        let mut password = create_unicode!("car1234");
        
        let false_bool: BOOLEAN = false.into();
        assert_eq!(unsafe{ PasswordFilter(null_mut(), null_mut(), &mut password, 0) }, false_bool);
    }

    #[test]
    fn PasswordFilter_emptypassword() {
        let mut password = create_unicode!("");

        let false_bool: BOOLEAN = false.into();
        assert_eq!(unsafe{ PasswordFilter(null_mut(), null_mut(), &mut password, 0) }, false_bool);
    }
}