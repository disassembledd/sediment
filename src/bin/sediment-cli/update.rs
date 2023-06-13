use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
use std::{io::Write, fs::OpenOptions};
use sha1::{Sha1, Digest};
use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about)]
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

pub fn main(options: Update) {
    if let Some(add_compromised) = options.add_compromised_password {
        // Retrieve download path from registry
        let dl_path: String = {
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            let app_key = hklm
                .create_subkey("SOFTWARE\\sediment")
                .expect("Failed to open or create registry key");

            app_key.get_value("DownloadPath").expect("Failed to open 'DownloadPath' key")
        };

        // Open or create the user file
        let mut user_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(format!("{dl_path}\\user"))
            .expect("Failed to open or create user file");

        // Add each compromised password hash to the user file
        for compromised_pass in add_compromised {
            let mut hasher = Sha1::new();
            hasher.update(compromised_pass.as_bytes());
            let hash = hasher.finalize();
            let compromised_pass_hashed = format!("{hash:X}");
            writeln!(&mut user_file, "{compromised_pass_hashed}").expect("Failed to write to user file");
        }
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
