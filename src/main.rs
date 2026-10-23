use std::{
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    pin::pin,
    sync::atomic::{AtomicU64, Ordering},
};

use async_compression::tokio::bufread::{XzDecoder, ZstdDecoder};
use bstr::{ByteSlice, ByteVec, io::BufReadExt};
use futures::{StreamExt, TryStreamExt};
use harmonia_file_nar::{NarEvent, parse_nar};
use hyperscan::{Builder, DatabaseRef, Matching, StreamingDatabase, StreamingMode, pattern};
use tokio::io::AsyncRead;
use tokio_util::{bytes::Bytes, io::ReaderStream};

use crate::{
    logging::Diagnostic,
    narinfo::{Compression, get_nar},
};

mod logging;
mod narinfo;

const STORE_PATH: &str = "/nix/store/";
const CACHE_SITE: &str = "https://cache.nixos.org/";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = std::io::stdin().lock();

    // All arguments should be store paths.
    let store_paths = stdin.byte_lines().flatten();

    let (logging_worker, ref logging_tx) = logging::get_worker();

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
                        let _ = logging_tx
                            .send(Diagnostic::Error(
                                name.into_string_lossy(),
                                format!("narinfo failed: '{err}'"),
                            ))
                            .await;
                        return vec![];
                    }
                },
                Err(err) => {
                    let _ = logging_tx
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
            let _ = logging_tx.send(Diagnostic::Start(name.to_string())).await;

            // Get the nar path
            let url = narinfo.get_nar_url();

            // Get the compression type
            let compression = narinfo.get_nar_compression();

            let size = narinfo.get_nar_filesize();
            total_processed.fetch_add(size, Ordering::Relaxed);

            let compressed_bytes = get_nar(client, url).await;

            // Wrap in a zstd decoder
            let decompressed_bytes: Box<dyn AsyncRead> = match compression {
                Compression::Zstd => Box::new(ZstdDecoder::new(compressed_bytes)),
                Compression::Xz => Box::new(XzDecoder::new(compressed_bytes)),
                Compression::Unknown => {
                    let _ = logging_tx
                        .send(Diagnostic::Error(
                            name.to_string(),
                            format!("Unknown compression"),
                        ))
                        .await;
                    return vec![];
                }
            };
            let decompressed_bytes = Box::into_pin(decompressed_bytes);

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

            let _ = logging_tx.send(Diagnostic::Finish(name.to_string())).await;
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

    let _ = logging_tx.send(Diagnostic::Result(output)).await;
    let _ = logging_worker.await; // Must await or else the process usually shuts down before the results are printed

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
