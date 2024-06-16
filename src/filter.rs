use log::error;
use sha1::{Digest, Sha1};
use std::{
    collections::hash_map::DefaultHasher,
    fs::File,
    hash::{Hash, Hasher},
    io::Read,
    os::windows::prelude::FileExt, path::Path,
};
use windows_registry::LOCAL_MACHINE;
use windows_result::Result;
use xorf::prelude::bfuse::hash_of_hash;
use zeroize::Zeroize;

/// Checks for the given password within the filter data structure
pub(crate) fn check_pass_in_filter(password: &str) -> bool {
    let (file_name, key) = get_name_and_key(password);
    let filter_path = match get_filter_path() {
        Ok(path) => path,
        Err(err) => {
            error!("Failed to retrieve path to filter files:\n{err:?}");
            return false;
        }
    };

    let mut filter_file = match File::open(Path::new(&filter_path).join(file_name)) {
        Ok(filter_file) => filter_file,
        Err(err) => {
            error!("Failed to open filter file:\n{err:?}");
            return false;
        }
    };

    let (seed, segment_length, segment_length_mask, segment_count_length) =
        get_filter_metadata(&mut filter_file);
    if segment_count_length % segment_length != 0 {
        error!("Filter file appears to be corrupt.");
        return false;
    }

    let hash = xorf::prelude::mix(key, seed);
    let mut fprint = xorf::fingerprint!(hash) as u8;

    let (h0, h1, h2) = get_filter_indices(
        &mut filter_file,
        hash_of_hash(
            hash,
            segment_length,
            segment_length_mask,
            segment_count_length,
        ),
    );

    fprint ^= h0 ^ h1 ^ h2;
    fprint != 0
}

/// Consumes the given password, zeroizing it and its hashes
/// and providing the filter's file name and key in the process.
fn get_name_and_key(password: &str) -> (String, u64) {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let mut password_hashed = format!("{hash:X}");

    let mut hasher = DefaultHasher::new();
    password_hashed.hash(&mut hasher);

    let name = password_hashed[..2].to_string();
    let key = hasher.finish();

    password_hashed.zeroize();
    (name, key)
}

/// Retrieves the `FilterPath` key from the registry.
fn get_filter_path() -> Result<String> {
    let app_key = LOCAL_MACHINE.create("SOFTWARE\\Sediment")?;
    app_key.get_string("FilterPath")
}

/// Reads the first 20 bytes from the filter file for the
/// metadata necessary to compute the hash indices.
fn get_filter_metadata(filter_file: &mut File) -> (u64, u32, u32, u32) {
    let mut buffer = [0; 20];
    filter_file.read_exact(&mut buffer).unwrap();

    let seed = u64::from_le_bytes(buffer[..8].try_into().unwrap());
    let segment_length = u32::from_le_bytes(buffer[8..12].try_into().unwrap());
    let segment_length_mask = u32::from_le_bytes(buffer[12..16].try_into().unwrap());
    let segment_count_length = u32::from_le_bytes(buffer[16..].try_into().unwrap());

    (
        seed,
        segment_length,
        segment_length_mask,
        segment_count_length,
    )
}

/// Seeks and reads 3 different bytes based on the hash indices
/// provided in `hashes`.
fn get_filter_indices(filter_file: &mut File, hashes: (u32, u32, u32)) -> (u8, u8, u8) {
    let mut buffer = [0; 1];
    filter_file
        .seek_read(&mut buffer, (20 + hashes.0) as u64)
        .unwrap();
    let h0 = buffer[0];

    filter_file
        .seek_read(&mut buffer, (20 + hashes.1) as u64)
        .unwrap();
    let h1 = buffer[0];

    filter_file
        .seek_read(&mut buffer, (20 + hashes.2) as u64)
        .unwrap();
    let h2 = buffer[0];

    (h0, h1, h2)
}
