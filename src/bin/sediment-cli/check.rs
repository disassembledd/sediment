use sediment_rs::PassInFilter;
use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about)]
pub struct Check {
    /// Password to check for within filter.
    #[arg(long)]
    password: String
}

pub fn main(options: Check) {
    if PassInFilter(options.password) {
        println!("Password found in compromised password list.");
    } else {
        println!("Password not found.")
    }
}