use std::{fs::{File, read_dir, rename}, time::Duration, num::NonZeroU32, sync::{Arc, atomic::{AtomicBool, Ordering}}, collections::{HashMap, hash_map::DefaultHasher}, io::{Read, Write, Seek, BufReader, BufRead}, path::{PathBuf, Path}, hash::{Hash, Hasher}, ffi::OsStr, rc::Rc, cell::Cell};
use governor::{RateLimiter, Quota, Jitter, state::{NotKeyed, InMemoryState}, clock::{QuantaClock, QuantaInstant}, middleware::NoOpMiddleware};
use flate2::{write::GzEncoder, read::GzDecoder, Compression};
use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::mpsc::{self, Sender};
use reqwest::StatusCode;
use xorf::BinaryFuse8;
use clap::Parser;

const BASE_URL: &str = "https://api.pwnedpasswords.com/range/";
type Limiter = RateLimiter<NotKeyed, InMemoryState, QuantaClock, NoOpMiddleware<QuantaInstant>>;

#[derive(Parser)]
#[clap(author, version, about)]
pub struct Download {
    /// Sets the path to download the hashes themselves.
    /// Defaults to the 'Path' key in the app's registry.
    #[arg(long)]
    pub download_path: Option<PathBuf>,

    /// Sets the path to parse the downloaded hashes into
    /// the filter data structure. Defaults to the 'FilterPath'
    /// key in the app's registry.
    #[arg(long)]
    pub filter_path: Option<PathBuf>
}

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

pub async fn main(ctrlc_handler: Arc<AtomicBool>, download_path: Option<PathBuf>, filter_path: Option<PathBuf>) {
    let client = reqwest::Client::new();
    let progress_bar = ProgressBar::new(0xFFFFFu64).with_style(ProgressStyle::with_template("[{elapsed_precise}] {msg} {wide_bar} {human_pos}/{human_len}").unwrap());

    // Retrieve app and download path from registry
    let (app_path, dl_path) = {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let app_key = match hklm.create_subkey("SOFTWARE\\sediment") {
            Ok(key) => key,
            Err(_) => {
                progress_bar.abandon_with_message("Cannot open registry key. Are you running as admin?");
                return;
            }
        };

        let app: String = match app_key.get_value("Path") {
            Ok(path) => path,
            Err(_) => {
                progress_bar.abandon_with_message("Could not find 'Path' key. Is the installation corrupt?");
                return;
            }
        };

        let download: String = match download_path {
            Some(path) => path.to_string_lossy().to_string(),
            None => match app_key.get_value("DownloadPath") {
                Ok(path) => path,
                Err(_) => {
                    progress_bar.abandon_with_message("Could not find 'DownloadPath' key. Is the installation corrupt?");
                    return;
                }
            }
        };

        (app, download)
    };

    let download_state = match sled::open(format!("{app_path}\\state")) {
        Ok(db) => db,
        Err(_account_name) => {
            progress_bar.abandon_with_message("Could not open state database. Are the permissions correct?");
            return;
        }
    };
    
    // Set up environment for downloading
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
    let mut range_states: HashMap<String, Vec<String>> = HashMap::new();

    // Read all download results as they come through
    while let Some(res) = rx.recv().await {
        match res {
            Ok((range, etag, content)) => {
                let range_name = range[..2].to_owned();
                let filepath = format!("{dl_path}\\{range_name}.temp");

                let stream = range_streams.entry(range_name.clone())
                    .or_insert(GzEncoder::new(File::create(filepath).expect("Failed to open file"), Compression::new(9)));
                
                for line in content.lines() {
                    let hash = range.clone() + line.split(':').next().unwrap() + "\r\n";
                    stream.write_all(hash.as_bytes()).expect("Failed to write hash into file");
                }

                range_states.entry(range_name).or_insert(Vec::new()).push(etag);
                progress_bar.inc(1);
            },
            Err(err) => {
                println!("Encountered an error in a download:\n{err:?}");
            }
        }
    }
    
    let user_data = if Path::new(&format!("{dl_path}\\user")).exists() {
        match File::open(format!("{dl_path}\\user")) {
            Ok(file) => {
                Some(BufReader::new(file).lines().flatten().collect::<Vec<String>>())
            },
            Err(err) => {
                println!("Encountered an error opening existing user file: {err:?}");
                None
            }
        }
    } else {
        None
    };

    progress_bar.set_message("Finishing streams...");
    for (range, mut stream) in range_streams.into_iter() {
        // Add hashes from user file
        if let Some(user_data) = user_data.clone() {
            match stream.get_mut().rewind() {
                Ok(_) => {},
                Err(err) => {
                    println!("Encountered an error seeking to start of stream: {err:?}");
                    continue;
                }
            }

            // Get hashes matching current range
            let mut hashes = Vec::new();
            for hash in user_data {
                if hash[..2] == range {
                    hashes.push(hash);
                }
            }

            // Read the current stream for checking duplicates
            let mut stream_data = String::new();
            match stream.read_to_string(&mut stream_data) {
                Ok(_) => {},
                Err(err) => {
                    println!("Encountered an error reading the stream data: {err:?}");
                    continue;
                }
            }

            // Remove duplicates from `hashes`
            for hash in stream_data.lines() {
                hashes.retain(|h| h != hash);
            }

            // Write user hashes to stream
            for hash in hashes {
                stream.write_all(hash.as_bytes()).expect("Failed to write hash into file");
            }
        }

        // Finish the Gzip stream and drop the underlying File
        match stream.finish() {
            Ok(writer) => drop(writer),
            Err(err) => {
                println!("Encountered an error closing a stream: {err:?}");
                continue;
            }
        }

        // Replace previous downloaded range with results from tempfile
        match rename(format!("{dl_path}\\{range}.temp"), format!("{dl_path}\\{range}")) {
            Ok(_) => {
                // On successful move, save download state of all ranges involved
                for etag in range_states.remove(&range).expect("Encountered an error retrieving expected range states") {
                    download_state.insert(range.clone(), etag.as_bytes()).expect("Failed to insert into state db");
                }
            },
            Err(err) => println!("Encountered an error overwriting destination file: {err:?}")
        }
    }

    let filter_path: String = match filter_path {
        Some(path) => path.to_string_lossy().to_string(),
        None => {
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            // Safe to unwrap if first call was successful
            let app_key = hklm.create_subkey("SOFTWARE\\sediment").unwrap();
    
            match app_key.get_value("FilterPath") {
                Ok(path) => path,
                Err(_) => {
                    progress_bar.abandon_with_message("Could not find 'FilterPath' key. Is the installation corrupt?");
                    return;
                }
            }
        }
    };
    
    progress_bar.set_message("Converting hashes into filter structure...");
    match read_dir(dl_path) {
        Ok(dir_iter) => {
            for entry in dir_iter {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(err) => {
                        println!("Failed to get directory entry: {err:?}");
                        continue;
                    }
                };

                let path = entry.path();
                let file_name = path.file_name().unwrap_or(OsStr::new("")).to_str().unwrap();
                if path.is_file() && !path.ends_with(".temp") && file_name != "user" {
                    let hashes = {
                        let file = match File::open(path.clone()) {
                            Ok(file) => file,
                            Err(err) => {
                                println!("Failed to open hash file: {err:?}");
                                continue;
                            }
                        };

                        let mut decoder = GzDecoder::new(file);
                        let mut hashes = String::new();
                        match decoder.read_to_string(&mut hashes) {
                            Ok(_) => {},
                            Err(err) => {
                                println!("Failed to read hash file: {err:?}");
                                continue;
                            }
                        }

                        hashes
                    };
    
                    let hashes_array = hashes.lines()
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
                                progress_bar.set_message("Failed to create filter, trying again...");
                                continue;
                            }
                        }
                    };
    
                    let file_name = path.file_name().unwrap().to_string_lossy().to_string();
                    // Scope to drop `output_file` when finished writing
                    {
                        let mut output_file = match File::create(format!("{filter_path}\\{file_name}.temp")) {
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
                            output_file.write_all(&filter.segment_count_length.to_le_bytes())
                        ];
        
                        if metadata_results.into_iter().any(|res| res.is_err()) {
                            println!("Failed to write filter metadata");
                            continue;
                        }
        
                        let data: Vec<u8> = filter.fingerprints.bytes().flatten().collect();
                        match output_file.write_all(&data) {
                            Ok(_) => {},
                            Err(err) => {
                                println!("Failed to write hash filter fingerprints to the file: {err:?}");
                                continue;
                            }
                        }
                    }

                    match rename(format!("{filter_path}\\{file_name}.temp"), format!("{filter_path}\\{file_name}")) {
                        Ok(_) => {},
                        Err(err) => println!("Failed to replace the hash filter file with the temp file: {err:?}")
                    }
                }
            }
        },
        Err(err) => {
            println!("Failed to read hash directory: {err:?}");
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