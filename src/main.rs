use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
    pin::pin,
    sync::atomic::{AtomicU64, Ordering},
};

use async_compression::tokio::bufread::ZstdDecoder;
use bstr::{ByteSlice, ByteVec};
use futures::{StreamExt, TryStreamExt};
use harmonia_file_nar::{NarEvent, parse_nar};
use hyperscan::{Builder, DatabaseRef, Matching, StreamingDatabase, StreamingMode, pattern};
use reqwest::{Client, Response};
use tokio::{io::AsyncWriteExt, sync::mpsc};
use tokio_util::{
    bytes::Bytes,
    io::{ReaderStream, StreamReader},
};

const STORE_PATH: &str = "/nix/store/";
const CACHE_SITE: &str = "https://cache.nixos.org/";

async fn get_narinfo(client: &Client, digest: &str) -> Result<Response, reqwest::Error> {
    // https://cache.nixos.org/005q6mj9lbz7vazzs6j2d68h8gda97ic.narinfo
    client
        .get(CACHE_SITE.to_string() + digest + ".narinfo")
        .send()
        .await
}

fn get_nar_url(narinfo: &str) -> &str {
    narinfo
        .lines()
        .skip(1)
        .next()
        .unwrap()
        .strip_prefix("URL: ")
        .unwrap()
}

fn get_nar_compression(narinfo: &str) -> &str {
    narinfo
        .lines()
        .skip(2)
        .next()
        .unwrap()
        .strip_prefix("Compression: ")
        .unwrap()
}

fn get_nar_name(narinfo: &str) -> &str {
    narinfo
        .lines()
        .next()
        .unwrap()
        .strip_prefix("StorePath: ")
        .unwrap()
}

fn get_nar_filesize(narinfo: &str) -> &str {
    narinfo
        .lines()
        .skip(4)
        .next()
        .unwrap()
        .strip_prefix("FileSize: ")
        .unwrap()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // All arguments should be store paths.
    let store_paths = std::env::args_os()
        .skip(1) // Skip arv0 since it's useless here
        .map(|path| {
            let mut path = path.into_encoded_bytes();

            // Remove the store path prefix
            path = path.replace(STORE_PATH, "");

            // Remove the name suffix, so only the digest is left
            path.resize(32, 0);

            // This better be a 32 byte nix digest
            assert_eq!(path.len(), 32, "Must be a nix store path");

            path.into_string().unwrap()
        });

    let (ref stderr_tx, mut stderr_rx) = mpsc::channel::<String>(16);

    // Little worker task that just writes stuff to stdout in a coherent manner
    tokio::spawn(async move {
        let mut output = tokio::io::stderr();
        while let Some(mess) = stderr_rx.recv().await {
            let _ = output.write_all(mess.as_bytes()).await;
        }
    });

    let scanning_db: StreamingDatabase =
        hyperscan::pattern! { r##"Electron/[0-9]*\.[0-9]*\.[0-9]*"##; SOM_LEFTMOST }
            .build()
            .unwrap();
    let scanning_db = scanning_db.as_ref();

    let client = &reqwest::Client::new();

    let total_processed = &AtomicU64::new(0);

    let found = futures::stream::iter(store_paths)
        .map(async move |digest| {
            let narinfo = match get_narinfo(client, &digest).await {
                Ok(res) => res.text().await.unwrap(),
                Err(_) => return vec![],
            };

            // Name for the store paths and output diagnostics
            let name = get_nar_name(&narinfo);
            let _ = stderr_tx.send(format!("Starting: {name}\n")).await;

            // Get the nar path
            let url = get_nar_url(&narinfo);

            // Get the compression type
            let compression = get_nar_compression(&narinfo);
            if compression != "zstd" {
                let _ = stderr_tx.send(format!("Failed: Not zstd, {name}\n")).await;

                return vec![];
            }

            let size = get_nar_filesize(&narinfo);
            total_processed.fetch_add(size.parse().unwrap(), Ordering::Relaxed);

            // Actually get the nar archive. I want to move this to function
            // but async types make me sad.
            let req = client
                .get(CACHE_SITE.to_string() + url)
                .send()
                .await
                .unwrap();
            let bytes = req
                .bytes_stream()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
            let compressed_bytes = StreamReader::new(bytes);

            // Wrap in a zstd decoder
            let decompressed_bytes = ZstdDecoder::new(compressed_bytes);

            // Then stuff it into parse events. We only want to scan files so filter to those.
            // Then call the scanning function.
            let mut parse_events = pin!(parse_nar(decompressed_bytes));

            let mut nar_finds: Vec<PathBuf> = vec![];

            // Buffer keeping track of the current nix store path we are looking at.
            let mut current_path = PathBuf::from(name);

            while let Some(event) = parse_events.try_next().await.unwrap() {
                match event {
                    NarEvent::File {
                        name,
                        executable,
                        reader,
                        size,
                    } => {
                        if let Some(_) = scanner(
                            scanning_db,
                            name.clone(),
                            executable,
                            size,
                            Box::new(reader),
                        )
                        .await
                        {
                            nar_finds.push(current_path.clone());
                        }
                    }
                    NarEvent::StartDirectory { name } => {
                        current_path.push(OsStr::from_bytes(&name))
                    }
                    NarEvent::EndDirectory => {
                        current_path.pop();
                    }
                    NarEvent::Symlink { .. } => continue,
                }
            }

            let _ = stderr_tx.send(format!("Finished: {name}\n")).await;
            return nar_finds;
        })
        .buffer_unordered(8);

    let output: Vec<_> = found.collect().await;
    println!("found: {:?}", output);
    println!(
        "Total processed: {} MiB",
        total_processed.load(Ordering::Relaxed) >> 20
    );

    Ok(())
}

// Yeah scan that file. Do ur stuff.
async fn scanner(
    db: &DatabaseRef<StreamingMode>,
    _: Bytes,
    executable: bool,
    _: u64,
    reader: Box<dyn tokio::io::AsyncBufRead>,
) -> Option<Vec<usize>> {
    if !executable {
        return None;
    }

    let mut stream = ReaderStream::new(Box::into_pin(reader));

    let mut found = Vec::new();

    // Allocate the buffer needed for scanning in this task.
    let scratch = db.alloc_scratch().unwrap();
    let scanner = db.open_stream().unwrap();

    // What to do when a match is found. Current just store the index of the start
    // of the match
    let mut cb = |_, start, _, _| {
        found.push(start as usize);

        Matching::Continue
    };

    // Scan
    while let Some(chunk) = stream.next().await {
        scanner.scan(chunk.unwrap(), &scratch, &mut cb).unwrap()
    }

    scanner.close(&scratch, cb).unwrap();

    if !found.is_empty() { Some(found) } else { None }
}
