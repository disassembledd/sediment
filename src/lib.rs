#![allow(non_snake_case)]
use std::{collections::{HashMap, hash_map::DefaultHasher}, sync::RwLock};
use windows_sys::Win32::Foundation::*;
use xorf::{BinaryFuse8, HashProxy};
use once_cell::sync::OnceCell;

type HashFuse = HashProxy<String, DefaultHasher, BinaryFuse8>;
static FILTER: OnceCell<RwLock<HashMap<String, HashFuse>>> = OnceCell::new();

pub extern "system" fn InitializeChangeNotify() -> BOOLEAN {
    if FILTER.set(RwLock::new(HashMap::new())).is_err() {
        return false.into()
    }

    // thread::spawn(move || {
    //     // TODO: Handle `FILTER` being updated when necessary.
    // });

    true.into()
}

pub extern "system" fn PasswordChangeNotify(
    _username: *mut UNICODE_STRING,
    _relative_id: u32,
    _new_password: *mut UNICODE_STRING
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub extern "system" fn PasswordFilter(
    _account_name: *mut UNICODE_STRING,
    _full_name: *mut UNICODE_STRING,
    _password: *mut UNICODE_STRING,
    _set_operation: BOOLEAN
) -> BOOLEAN {
    true.into()
}