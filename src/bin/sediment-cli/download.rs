use std::{fs::{File, OpenOptions}, time::Duration, num::NonZeroU32, sync::{Arc, atomic::{AtomicBool, Ordering}}, collections::HashMap, io::Write, path::PathBuf};
use governor::{RateLimiter, Quota, Jitter, state::{NotKeyed, InMemoryState}, clock::{QuantaClock, QuantaInstant}, middleware::NoOpMiddleware};
use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};
use indicatif::{ProgressBar, ProgressStyle};
use flate2::{write::GzEncoder, Compression};
use tokio::sync::mpsc::{self, Sender};
use reqwest::StatusCode;
use clap::Parser;

const BASE_URL: &str = "https://api.pwnedpasswords.com/range/";
type Limiter = RateLimiter<NotKeyed, InMemoryState, QuantaClock, NoOpMiddleware<QuantaInstant>>;

#[derive(Parser)]
#[clap(author, version, about)]
pub struct Download {}

#[derive(Clone)]
struct DownloadHandler {
    client: reqwest::Client,
    progress_bar: ProgressBar,
    download_state: sled::Db,
    ctrlc_handler: Arc<AtomicBool>,
    limiter: Arc<Limiter>
}

impl DownloadHandler {
    pub fn new(client: reqwest::Client, progress_bar: ProgressBar, download_state: sled::Db, ctrlc_handler: Arc<AtomicBool>, limiter: Arc<Limiter>) -> Self {
        progress_bar.set_message("Starting...");
        Self { client, progress_bar, download_state, ctrlc_handler, limiter }
    }

    pub async fn start_download(self, tx: Sender<Result<(String, String, String), reqwest::Error>>) {
        self.progress_bar.set_message("Pages visited");

        for range in generate_ranges() {
            self.limiter.until_ready_with_jitter(Jitter::up_to(Duration::from_millis(1500))).await;
            if !self.ctrlc_handler.load(Ordering::SeqCst) {
                self.progress_bar.set_message(format!("Stopping worker {range}..."));
                return;
            }

            let tx = tx.clone();
            let url = format!("{BASE_URL}{range}");

            let self_clone = self.clone();
            tokio::spawn(self_clone.download_range(tx, url, range));
        }
    }

    async fn download_range(self, tx: Sender<Result<(String, String, String), reqwest::Error>>, url: String, range: String) {
        self.limiter.until_ready_with_jitter(Jitter::up_to(Duration::from_millis(500))).await;
        if !self.ctrlc_handler.load(Ordering::SeqCst) {
            self.progress_bar.set_message(format!("Stopping worker {range}..."));
            return;
        }

        let res = if let Some(etag) = self.download_state.get(range.clone()).expect("Failed to check db") {
            self.client.get(url).header("If-None-Match", String::from_utf8(etag.to_vec()).unwrap()).send()
        } else {
            self.client.get(url).send()
        }.await;
        
        match res {
            Ok(resp) => {
                if resp.status() == StatusCode::NOT_MODIFIED {
                    self.progress_bar.inc(1);
                    return;
                }

                let headers = resp.headers();
                let etag = headers["etag"].to_str().unwrap().to_string();

                match resp.text().await {
                    Ok(content) => {
                        tx.send(Ok((range, etag, content))).await.expect("Failed to send content through channel");
                    },
                    Err(err) => tx.send(Err(err)).await.expect("Failed to send text error through channel")
                };
            },
            Err(err) => {
                tx.send(Err(err)).await.expect("Failed to send response error through channel");
            }
        }
    }
}

fn generate_ranges() -> Vec<String> {
    (0x00000..=0xFFFFF)
        .map(|i: i32| format!("{i:05X}"))
        .collect()
}

pub async fn main(ctrlc_handler: Arc<AtomicBool>, download_path: Option<PathBuf>) {
    let client = reqwest::Client::new();
    let progress_bar = ProgressBar::new(0xFFFFFu64).with_style(ProgressStyle::with_template("[{elapsed_precise}] {msg} {wide_bar} {human_pos}/{human_len}").unwrap());

    let app_path: String = {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let app_key = match hklm.create_subkey("SOFTWARE\\sediment") {
            Ok(key) => key,
            Err(_) => {
                progress_bar.abandon_with_message("Cannot open registry key. Are you running as admin?");
                return;
            }
        };

        match app_key.get_value("Path") {
            Ok(path) => path,
            Err(_) => {
                progress_bar.abandon_with_message("Could not find 'Path' key. Is the installation corrupt?");
                return;
            }
        }
    };

    let download_state = match sled::open(format!("{app_path}\\state")) {
        Ok(db) => db,
        Err(_account_name) => {
            progress_bar.abandon_with_message("Could not open state database. Are the permissions correct?");
            return;
        }
    };
    
    let (tx, mut rx) = mpsc::channel(256);
    let limiter = Arc::new(RateLimiter::direct(Quota::per_second(NonZeroU32::new(384).unwrap())));
    let progress_clone = progress_bar.clone();
    let state_clone = download_state.clone();
    let ctrlc_clone = ctrlc_handler.clone();

    let download_handler = DownloadHandler::new(client, progress_clone, state_clone, ctrlc_clone, limiter);
    let task_tx = tx.clone();
    tokio::spawn(download_handler.start_download(task_tx));
    
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
                progress_bar.inc(1);
            },
            Err(err) => {
                println!("Encountered an error in a download:\n{err:?}");
            }
        }
    }

    progress_bar.set_message("Finishing streams...");
    for stream in range_streams.into_values() {
        match stream.finish() {
            Ok(_) => {},
            Err(err) => {
                println!("Encountered an error closing a stream: {err:?}");
            }
        }
    }

    if !ctrlc_handler.load(Ordering::SeqCst) {
        progress_bar.abandon_with_message("Downloads cancelled");
    } else {
        progress_bar.finish_with_message("Downloads finished");
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ranges_test() {
        let ranges = generate_ranges();

        assert_eq!(ranges.first(), Some(&String::from("00000")));
        assert_eq!(ranges.last(), Some(&String::from("FFFFF")));
        assert_eq!(ranges.len(), 1048576);
    }
}