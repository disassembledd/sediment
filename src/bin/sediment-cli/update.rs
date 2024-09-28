use clap::Parser;
use flate2::read::GzDecoder;
use sha1::{Digest, Sha1};
use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    fs::{rename, File, OpenOptions},
    hash::{Hash, Hasher},
    io::{Read, Write},
    path::Path,
};
use windows_registry::LOCAL_MACHINE;
use xorf::BinaryFuse8;

#[derive(Parser)]
#[clap(author, version, about)]
/// Configuration for the `update` subcommand.
pub struct Update {
    /// Adds a compromised password to the hash filters.
    #[arg(long)]
    add_compromised_password: Option<Vec<String>>,

    /// Adds a banned word to the word store.
    #[arg(long)]
    add_banned_word: Option<Vec<String>>,

    /// Removes a banned word from the word store.
    #[arg(long)]
    remove_banned_word: Option<Vec<String>>,
}

/// Adds the provided passwords to the compromised password filter
/// structure. If a duplicate is found, it is ignored.
fn add_compromised_pass(passwords: Vec<String>) {
    // Retrieve download path from registry
    let (dl_path, filter_path) = {
        let app_key = LOCAL_MACHINE
            .create("SOFTWARE\\Sediment")
            .expect("Failed to open or create registry key");

        let dl_path: String = app_key
            .get_string("DownloadPath")
            .expect("Failed to open 'DownloadPath' key");
        let filter_path: String = app_key
            .get_string("FilterPath")
            .expect("Failed to open 'FilterPath' key");

        (dl_path, filter_path)
    };

    // Open or create the user file
    let mut user_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(Path::new(&dl_path).join("user"))
        .expect("Failed to open or create user file");

    // Adds each compromised password hash to the user file,
    // checking for duplicates in existing files and writing
    // all unique hashes to a Vec for updating the filter.
    let mut hashes_to_add = HashMap::<String, Vec<String>>::new();
    let mut processed_files = HashSet::<String>::new();
    println!("Writing passwords to user file...");
    for compromised_pass in passwords {
        let mut hasher = Sha1::new();
        hasher.update(compromised_pass.as_bytes());
        let hash = hasher.finalize();
        let compromised_pass_hashed = format!("{hash:X}");
        let pass_range = compromised_pass_hashed[..2].to_owned();
        writeln!(&mut user_file, "{compromised_pass_hashed}")
            .expect("Failed to write to user file");

        if !processed_files.contains(&pass_range) {
            if let Ok(file) = File::open(Path::new(&dl_path).join(&pass_range)) {
                let mut decoder = GzDecoder::new(file);
                let mut hashes = String::new();
                decoder
                    .read_to_string(&mut hashes)
                    .expect("Failed to read hashes from file");

                for hash in hashes.lines() {
                    hashes_to_add
                        .entry(pass_range.clone())
                        .and_modify(|data| data.push(hash.to_string()))
                        .or_insert(vec![hash.to_string()]);
                }

                processed_files.insert(pass_range.clone());
            }
        }

        hashes_to_add
            .entry(pass_range)
            .and_modify(|data| {
                if !data.contains(&compromised_pass_hashed) {
                    data.push(compromised_pass_hashed.clone());
                }
            })
            .or_insert(vec![compromised_pass_hashed]);
    }

    // Add unique hashes to filters
    println!("Adding passwords to filter...");
    for (range, hashes) in hashes_to_add {
        let hashes_array = hashes
            .into_iter()
            .map(|h| {
                let mut hasher = DefaultHasher::new();
                h.trim().hash(&mut hasher);
                hasher.finish()
            })
            .collect::<Vec<u64>>();

        let filter = loop {
            match BinaryFuse8::try_from(&hashes_array) {
                Ok(filter) => break filter,
                Err(_) => {
                    println!("Failed to create filter, trying again...");
                    continue;
                }
            }
        };

        // Scope to drop `output_file` when finished writing
        {
            let mut output_file =
                match File::create(Path::new(&filter_path).join(format!("{range}.temp"))) {
                    Ok(file) => file,
                    Err(err) => {
                        println!("Failed to create temp hash filter file: {err:?}");
                        continue;
                    }
                };

            let metadata_results = vec![
                output_file.write_all(&filter.seed.to_le_bytes()),
                output_file.write_all(&filter.segment_length.to_le_bytes()),
                output_file.write_all(&filter.segment_length_mask.to_le_bytes()),
                output_file.write_all(&filter.segment_count_length.to_le_bytes()),
            ];

            if metadata_results.into_iter().any(|res| res.is_err()) {
                println!("Failed to write filter metadata");
                continue;
            }

            let data: Vec<u8> = filter.fingerprints.bytes().flatten().collect();
            match output_file.write_all(&data) {
                Ok(_) => {}
                Err(err) => {
                    println!("Failed to write hash filter fingerprints to the file: {err:?}");
                    continue;
                }
            }
        }

        match rename(
            Path::new(&filter_path).join(format!("{range}.temp")),
            Path::new(&filter_path).join(range),
        ) {
            Ok(_) => {}
            Err(err) => {
                println!("Failed to replace the hash filter file with the temp file: {err:?}")
            }
        }
    }
}

/// Main entrypoint for the `update` subcommand.
pub fn main(options: Update) {
    if let Some(passwords) = options.add_compromised_password {
        println!("Adding compromised password(s)...");
        add_compromised_pass(passwords);
        println!("Finished!")
    }

    if let Some(_add_banned) = options.add_banned_word {
        // Handle adding a banned word
        todo!()
    }

    if let Some(_remove_banned) = options.remove_banned_word {
        // Handle removing a banned word
        todo!()
    }
}
