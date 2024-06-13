use std::{ffi::OsStr, io::Result, mem};
use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE, types::FromRegValue};
use zeroize::Zeroizing;


pub fn get_regkey_value<T: FromRegValue, N: AsRef<OsStr>>(key: N) -> Result<T> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let app_key = hklm.create_subkey("SOFTWARE\\sediment")?;

    app_key.get_value(key)
}

pub(crate) fn replace_symbols(password: &mut String) {
    let mut bytes = mem::take(password).into_bytes();
    for byte in bytes.iter_mut() {
        *byte = match byte {
            b'0' => b'o',
            b'1' => b'l',
            b'2' => b'z',
            b'3' => b'e',
            b'4' => b'a',
            b'5' => b's',
            b'6' => b'g',
            b'7' => b't',
            b'8' => b'b',
            b'9' => b'q',
            b'!' => b'i',
            b'@' => b'a',
            b'#' => b'h',
            b'$' => b's',
            b'%' => b'z',
            &mut b => b
        };
    }

    *password = String::from_utf8(bytes).expect("Invalid UTF-8");
}

fn PasswordFilter(
    password: String,
) -> bool {
    let mut password = Zeroizing::new(password);

    let normalize: u32 = match get_regkey_value("NormalizeFlag") {
        Ok(norm) => norm,
        Err(_) => {
            return false;
        }
    };

    if normalize == 1 {
        replace_symbols(&mut password);
    }

    // TODO: Copy the logic necessary from the cdylib over for the binary to use.
    // if !filter::check_pass_in_filter(password.as_str()) {
    //     return false;
    // }

    true
}