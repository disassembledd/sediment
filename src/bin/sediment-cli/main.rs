use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use clap::{Parser, Subcommand};

mod download;

#[derive(Parser)]
#[clap(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand)]
enum Commands {
    Download(download::Download)
}

fn main() {
    let cli = Cli::parse();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let handler = Arc::new(AtomicBool::new(true));
    let handler_clone = handler.clone();
    ctrlc::set_handler(move || {
        handler_clone.store(false, Ordering::SeqCst);
    }).expect("Failed to set Ctrl+C handler");
    
    match cli.command {
        Commands::Download(download) => {
            rt.block_on(download::main(handler, download.download_path, download.filter_path));
        }
    }
}