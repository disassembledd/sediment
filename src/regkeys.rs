use std::{ffi::OsStr, io::Result};
use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE, types::FromRegValue};

pub fn get_regkey_value<T: FromRegValue, N: AsRef<OsStr>>(key: N) -> Result<T> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let app_key = hklm.create_subkey("SOFTWARE\\sediment")?;

    app_key.get_value(key)
}