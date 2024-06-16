use windows_registry::{LOCAL_MACHINE, Value};
use windows_result::Result;

pub fn get_regkey_value<T: AsRef<str>>(key: T) -> Result<Value> {
    let app_key = LOCAL_MACHINE.create("SOFTWARE\\sediment")?;
    app_key.get_value(key)
}