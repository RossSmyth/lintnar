use std::{
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    pin::pin,
    sync::atomic::{AtomicU64, Ordering},
};

use async_compression::tokio::bufread::ZstdDecoder;
use bstr::{ByteSlice, ByteVec, io::BufReadExt};
use futures::{StreamExt, TryStreamExt};
use harmonia_file_nar::{NarEvent, parse_nar};
use hyperscan::{Builder, DatabaseRef, Matching, StreamingDatabase, StreamingMode, pattern};
use tokio::{io::AsyncWriteExt, sync::mpsc};
use tokio_util::{
    bytes::Bytes,
    io::{ReaderStream, StreamReader},
};

use crate::narinfo::Compression;

mod narinfo;

const STORE_PATH: &str = "/nix/store/";
const CACHE_SITE: &str = "https://cache.nixos.org/";

enum Diagnostic {
    Start(String),
    Finish(String),
    Result(Vec<PathBuf>),
    Error(String, String),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = std::io::stdin().lock();

    // All arguments should be store paths.
    let store_paths = stdin.byte_lines().flatten();

    // For sending stuff to stderr
    let (ref stdout_tx, mut stdout_rx) = mpsc::channel::<Diagnostic>(16);

    // Little worker task that just writes stuff to stdout in a coherent manner
    let stdout_worker = tokio::spawn(async move {
        let mut output = tokio::io::stdout();
        while let Some(mess) = stdout_rx.recv().await {
            let jsonl;
            let mut exit = false;
            match mess {
                Diagnostic::Start(name) => {
                    // { message: "start", path: "..." }
                    jsonl = format!(r##"{{"message": "start", "path": "{}"}}"##, name);
                }
                Diagnostic::Finish(name) => {
                    // { message: "start", path: "..." }
                    jsonl = format!(r##"{{"message": "finish", "path": "{}"}}"##, name);
                }
                Diagnostic::Error(name, message) => {
                    // { message: "error", "path": "...", "error": "..." }
                    jsonl = format!(
                        r##"{{"message": "error", "path": "{}", "error": "{}"}}"##,
                        name, message
                    );
                }
                Diagnostic::Result(output) => {
                    // { message: "error", "path": "...", "error": "..." }
                    jsonl = format!(r##"{{"message": "result", "matches": {:?} }}"##, output);
                    exit = true;
                }
            }
            let _ = output.write_all((jsonl + "\n").as_bytes()).await;
            if exit {
                return;
            }
        }
    });

    // The regex that is being scanned for. The FSM is shared across
    // all tasks.
    let ref scanning_db: StreamingDatabase =
        hyperscan::pattern! { r##"BEGIN CERTIFICATE"##; SOM_LEFTMOST }
            .build()
            .unwrap();

    // Reqwest client shared with all tasks
    let ref client = reqwest::Client::new();

    // For diagnostics
    let ref total_processed = AtomicU64::new(0);

    let found = futures::stream::iter(store_paths)
        .map(async move |name| {
            let digest = path_to_digest(&name);

            let narinfo = match narinfo::get_narinfo(client, &digest).await {
                Ok(res) => match res.text().await {
                    Ok(info) => info,
                    Err(err) => {
                        let _ = stdout_tx
                            .send(Diagnostic::Error(
                                name.into_string_lossy(),
                                format!("narinfo failed: '{err}'"),
                            ))
                            .await;
                        return vec![];
                    }
                },
                Err(err) => {
                    let _ = stdout_tx
                        .send(Diagnostic::Error(
                            name.into_string_lossy(),
                            format!("narinfo failed: '{err}'"),
                        ))
                        .await;
                    return vec![];
                }
            };
            let narinfo = narinfo::NarInfo::new(&narinfo);

            // Name for the store paths and output diagnostics
            // Unsure if this is better to use or the input store path
            let name = narinfo.get_nar_name();
            let _ = stdout_tx.send(Diagnostic::Start(name.to_string())).await;

            // Get the nar path
            let url = narinfo.get_nar_url();

            // Get the compression type
            let compression = narinfo.get_nar_compression();
            if compression != Compression::Zstd {
                let _ = stdout_tx
                    .send(Diagnostic::Error(
                        name.to_string(),
                        format!("not zstd, is {compression:?}"),
                    ))
                    .await;

                return vec![];
            }

            let size = narinfo.get_nar_filesize();
            total_processed.fetch_add(size, Ordering::Relaxed);

            // Actually get the nar archive. I want to move this to function
            // but async types make me sad.
            let req = client
                .get(CACHE_SITE.to_string() + url)
                .send()
                .await
                .unwrap();
            let bytes = req.bytes_stream().map_err(std::io::Error::other);
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
                        if scanner(
                            scanning_db,
                            name.clone(),
                            executable,
                            size,
                            Box::new(reader),
                        )
                        .await
                        .is_some()
                        {
                            let mut path = current_path.clone();
                            path.push(OsStr::from_bytes(&name));
                            nar_finds.push(path);
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

            let _ = stdout_tx.send(Diagnostic::Finish(name.to_string())).await;
            nar_finds
        })
        .buffer_unordered(std::thread::available_parallelism().unwrap().get());

    let output: Vec<_> = found
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .filter(|item| !item.is_empty())
        .flatten()
        .collect();

    let _ = stdout_tx.send(Diagnostic::Result(output)).await;
    let _ = stdout_worker.await.unwrap();

    eprintln!(
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

/// Nix store path to the drv digest string.
fn path_to_digest(path: &[u8]) -> String {
    // Remove the store path prefix
    // '/nix/store/3bfp9mlim5v39aabhwaj4hizl30mfr2q-source' -> '3bfp9mlim5v39aabhwaj4hizl30mfr2q-source'
    let mut out = path.replace(STORE_PATH, "");

    // Truncate the end
    // '3bfp9mlim5v39aabhwaj4hizl30mfr2q-source' -> '3bfp9mlim5v39aabhwaj4hizl30mfr2q'
    out.resize(32, 0);

    // To String, they will always be valid.
    out.into_string().unwrap()
}
