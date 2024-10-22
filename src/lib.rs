#![allow(non_snake_case)]
use core::slice;
use log::{error, info, warn};
use std::{ptr::null_mut, string::FromUtf16Error};
use windows_registry::Value;
use windows_sys::Win32::Foundation::*;
use zeroize::{Zeroize, Zeroizing};

mod filter;
mod normalize;
mod regkeys;

pub use regkeys::get_regkey_value;

/// Public exposure for testing the Win32 call and determining if
/// the given password was found within the filter structure.
pub fn PassInFilter(password: String) -> bool {
    let mut data = password.encode_utf16().collect::<Vec<u16>>();

    let mut password = UNICODE_STRING {
        Length: (data.len() * 2) as u16,
        MaximumLength: (data.capacity() * 2) as u16,
        Buffer: data.as_mut_ptr(),
    };

    let res = unsafe { PasswordFilter(null_mut(), null_mut(), &mut password, 0) };
    res == 0
}

/// Consumes the given `UNICODE_STRING` buffer, zeroizing it and
/// returning a Rust `String` in the process.
unsafe fn string_from_windows(
    unicode_string: *mut UNICODE_STRING,
) -> Result<String, FromUtf16Error> {
    let buffer = unsafe {
        slice::from_raw_parts_mut(
            (*unicode_string).Buffer,
            ((*unicode_string).Length / 2) as usize,
        )
    };
    let res = String::from_utf16(buffer);
    buffer.zeroize();

    res
}

/// Initializes the Event Log provider on first load.
#[no_mangle]
pub extern "system" fn InitializeChangeNotify() -> BOOLEAN {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(5));
        eventlog::init("Sediment", log::Level::Info).unwrap();
        info!("Successfully loaded password filter.");
    });

    true.into()
}

/// Logs if a user password was successfully changed.
///
/// ## Safety
/// Called by Windows whenever a user successfully changes
/// or sets their password.
#[no_mangle]
pub unsafe extern "system" fn PasswordChangeNotify(
    username: *mut UNICODE_STRING,
    _relative_id: u32,
    new_password: *mut UNICODE_STRING,
) -> NTSTATUS {
    if (*new_password).Length > 1 {
        let buffer = unsafe {
            slice::from_raw_parts_mut(
                (*new_password).Buffer,
                ((*new_password).Length / 2) as usize,
            )
        };
        buffer.zeroize();
    }

    let username = match string_from_windows(username) {
        Ok(username) => username,
        Err(err) => {
            error!("Failed to read username:\n{err:?}");
            return STATUS_SUCCESS;
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
#[no_mangle]
pub unsafe extern "system" fn PasswordFilter(
    account_name: *mut UNICODE_STRING,
    _full_name: *mut UNICODE_STRING,
    password: *mut UNICODE_STRING,
    _set_operation: BOOLEAN,
) -> BOOLEAN {
    if (*password).Length <= 1 {
        error!("Password was empty.");
        return false.into();
    }

    let user = match string_from_windows(account_name) {
        Ok(user) => Zeroizing::new(user),
        Err(_) => {
            error!("Failed to parse username.");
            Zeroizing::new(String::from("UNKNOWN"))
        }
    };

    let mut password = match string_from_windows(password) {
        Ok(password) => Zeroizing::new(password),
        Err(_) => {
            error!("Failed to parse password for {}.", user.as_str());
            return false.into();
        }
    };

    let normalize: u32 = match get_regkey_value("NormalizeFlag") {
        Ok(Value::U32(norm)) => norm,
        _ => {
            error!("Failed to retrieve 'NormalizeFlag' regkey.");
            return false.into();
        }
    };

    if normalize == 1 {
        normalize::replace_symbols(&mut password);
    }

    if !filter::check_pass_in_filter(password.as_str()) {
        warn!(
            "Password for {} failed compromised checklist.",
            user.as_str()
        );
        return false.into();
    }

    info!("Password for {} passed all checks.", user.as_str());
    true.into()
}

#[cfg(test)]
mod tests {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::*;

    use super::PasswordFilter;

    macro_rules! create_unicode {
        ( $data:expr ) => {{
            let mut data = String::from($data).encode_utf16().collect::<Vec<u16>>();

            UNICODE_STRING {
                Length: (data.len() * 2) as u16,
                MaximumLength: (data.capacity() * 2) as u16,
                Buffer: data.as_mut_ptr(),
            }
        }};
    }

    #[test]
    /// Asserts a valid response from `InitializeChangeNotify`.
    fn InitializeChangeNotify() {
        assert!(super::InitializeChangeNotify() > 0);
    }

    #[test]
    /// Asserts a valid response from `PasswordChangeNotify`.
    fn PasswordChangeNotify() {
        let mut username = create_unicode!("ChangeNotifyTester");
        let mut password = create_unicode!("");

        assert_eq!(
            unsafe { super::PasswordChangeNotify(&mut username, 0, &mut password) },
            0
        );
    }

    #[test]
    /// Asserts a true response with a known-good password.
    fn PasswordFilter_goodpassword() {
        let mut password = create_unicode!("VNTPJ23GvZh@Z@b72RJF");

        let true_bool: BOOLEAN = true.into();
        assert_eq!(
            unsafe { PasswordFilter(null_mut(), null_mut(), &mut password, 0) },
            true_bool
        );
    }

    #[test]
    /// Asserts a false response with a known-bad password.
    fn PasswordFilter_badpassword() {
        let mut password = create_unicode!("car1234");

        let false_bool: BOOLEAN = false.into();
        assert_eq!(
            unsafe { PasswordFilter(null_mut(), null_mut(), &mut password, 0) },
            false_bool
        );
    }

    #[test]
    /// Asserts a false response with an empty password.
    fn PasswordFilter_emptypassword() {
        let mut password = create_unicode!("");

        let false_bool: BOOLEAN = false.into();
        assert_eq!(
            unsafe { PasswordFilter(null_mut(), null_mut(), &mut password, 0) },
            false_bool
        );
    }
}
