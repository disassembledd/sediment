use clap::Parser;
use sediment_rs::PassInFilter;

#[derive(Parser)]
#[clap(author, version, about)]
/// Configuration for the `check` subcommand.
pub struct Check {
    /// Password to check for within filter.
    #[arg(long)]
    password: String,
}

/// Main entrypoint for the `check` subcommand.
pub fn main(options: Check) {
    if PassInFilter(options.password) {
        println!("Password found in compromised password list.");
    } else {
        println!("Password not found.")
    }
}
