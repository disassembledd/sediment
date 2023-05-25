use std::{fs::{File, OpenOptions}, time::Duration, num::NonZeroU32, sync::{Arc, atomic::{AtomicBool, Ordering}}, collections::HashMap, io::Write, path::PathBuf};
use indicatif::{ProgressBar, ProgressStyle};
use flate2::{write::GzEncoder, Compression};
use governor::{RateLimiter, Quota, Jitter};
use reqwest::StatusCode;
use tokio::sync::mpsc;
use clap::Parser;
use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};

const BASE_URL: &str = "https://api.pwnedpasswords.com/range/";

#[derive(Parser)]
#[clap(author, version, about)]
pub struct Download {}

fn generate_ranges() -> Vec<String> {
    (0x00000..=0xFFFFF)
        .map(|i: i32| format!("{i:05X}"))
        .collect()
}

pub async fn main(ctrlc_handler: Arc<AtomicBool>, download_path: Option<PathBuf>) {
    let client = reqwest::Client::new();
    
    let progress = ProgressBar::new(0xFFFFFu64).with_style(ProgressStyle::with_template("[{elapsed_precise}] {msg} {wide_bar} {human_pos}/{human_len}").unwrap());
    progress.set_message("Pages visited");

    let app_path: String = {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let app_key = match hklm.create_subkey("SOFTWARE\\sediment") {
            Ok(key) => key,
            Err(_) => {
                progress.abandon_with_message("Cannot open registry key. Are you running as admin?");
                return;
            }
        };

        match app_key.get_value("Path") {
            Ok(path) => path,
            Err(_) => {
                progress.abandon_with_message("Could not find 'Path' key. Is the installation corrupt?");
                return;
            }
        }
    };

    let download_state = match sled::open(format!("{app_path}\\state")) {
        Ok(db) => db,
        Err(_account_name) => {
            progress.abandon_with_message("Could not open state database. Are the permissions correct?");
            return;
        }
    };
    
    let (tx, mut rx) = mpsc::channel(256);
    let task_tx = tx.clone();
    let task_handler = ctrlc_handler.clone();
    let task_progress = progress.clone();
    let task_dl_state = download_state.clone();
    tokio::spawn(async move {
        let limiter = Arc::new(RateLimiter::direct(Quota::per_second(NonZeroU32::new(384).unwrap())));
        for range in generate_ranges() {
            limiter.until_ready_with_jitter(Jitter::up_to(Duration::from_millis(1500))).await;
            if !task_handler.load(Ordering::SeqCst) {
                task_progress.set_message(format!("Stopping worker {range}..."));
                return;
            }

            let tx = task_tx.clone();
            let url = format!("{BASE_URL}{range}");
            let client = client.clone();
            let progress = task_progress.clone();
            let download_state = task_dl_state.clone();
            let handler = task_handler.clone();
            let limiter = limiter.clone();
            
            tokio::spawn(async move {
                limiter.until_ready_with_jitter(Jitter::up_to(Duration::from_millis(500))).await;
                if !handler.load(Ordering::SeqCst) {
                    progress.set_message(format!("Stopping worker {range}..."));
                    return;
                }

                let res = if let Some(etag) = download_state.get(range.clone()).expect("Failed to check db") {
                    client.get(url).header("If-None-Match", String::from_utf8(etag.to_vec()).unwrap()).send()
                } else {
                    client.get(url).send()
                }.await;
                
                match res {
                    Ok(resp) => {
                        if resp.status() == StatusCode::NOT_MODIFIED {
                            progress.inc(1);
                            return;
                        }

                        let headers = resp.headers();
                        let etag = headers["etag"].to_str().unwrap().to_string();

                        match resp.text().await {
                            Ok(content) => {
                                tx.send(Ok((range.clone(), etag, content))).await.expect("Failed to send content through channel");
                            },
                            Err(err) => tx.send(Err(err)).await.expect("Failed to send text error through channel")
                        };
                    },
                    Err(err) => {
                        tx.send(Err(err)).await.expect("Failed to send response error through channel");
                    }
                }
            });
        }
    });

    drop(tx);
    let mut range_streams: HashMap<String, GzEncoder<File>> = HashMap::new();
    while let Some(res) = rx.recv().await {
        match res {
            Ok((range, etag, content)) => {
                let range_name = range[..2].to_owned();
                let mut filepath = range_name.clone();

                let download_path = download_path.clone();
                if download_path.is_some() {
                    filepath.insert_str(0, download_path.unwrap().to_str().unwrap());
                } else {
                    filepath.insert_str(0, format!("{app_path}\\downloads\\").as_str());
                }

                let stream = range_streams.entry(range_name).or_insert_with(move || {
                    let file = OpenOptions::new()
                                        .append(true)
                                        .create(true)
                                        .open(filepath).expect("Failed to open file");

                    GzEncoder::new(file, Compression::new(9))
                });
                
                for line in content.lines() {
                    let hash = range.clone() + line.split(':').next().unwrap() + "\r\n";
                    stream.write_all(hash.as_bytes()).expect("Failed to write hash into file");
                }

                download_state.insert(range, etag.as_bytes()).expect("Failed to insert into state db");
                progress.inc(1);
            },
            Err(err) => {
                println!("Encountered an error in a download:\n{err:?}");
            }
        }
    }

    progress.set_message("Finishing streams...");
    for stream in range_streams.into_values() {
        match stream.finish() {
            Ok(_) => {},
            Err(err) => {
                println!("Encountered an error closing a stream: {err:?}");
            }
        }
    }

    if !ctrlc_handler.load(Ordering::SeqCst) {
        progress.abandon_with_message("Downloads cancelled");
    } else {
        progress.finish_with_message("Downloads finished");
    }
}