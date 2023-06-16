use windows_sys::Win32::{System::Threading::{OpenProcessToken, GetCurrentProcess}, Security::{TOKEN_QUERY, TOKEN_ELEVATION, GetTokenInformation, TokenElevation}, Foundation::HANDLE};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use clap::{Parser, Subcommand};

mod download;
mod update;
mod check;


fn is_elevated() -> bool {
    let mut token_handle = HANDLE::default();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) } != 0 {
        let mut elevation = TOKEN_ELEVATION{ TokenIsElevated: 0 };
        if unsafe {
            GetTokenInformation(
            token_handle,
            TokenElevation,
            (&mut elevation) as *mut TOKEN_ELEVATION as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut 0
            )
        } != 0 {
            return elevation.TokenIsElevated != 0
        }
    }
    
    false
}

#[derive(Parser)]
#[clap(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand)]
enum Commands {
    Download(download::Download),
    Update(update::Update),
    Check(check::Check)
}

fn main() {
    if !is_elevated() {
        println!("Please run the CLI as administrator. It requires access to registry keys for configuration purposes.");
        return;
    }

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
        Commands::Download(options) => {
            rt.block_on(download::main(handler, options.download_path, options.filter_path));
        },
        Commands::Update(options) => {
            update::main(options)
        },
        Commands::Check(options) => {
            check::main(options)
        }
    }
}