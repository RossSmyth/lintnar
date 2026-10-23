use std::{
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    pin::pin,
    sync::atomic::{AtomicU64, Ordering},
};

use async_compression::tokio::bufread::{XzDecoder, ZstdDecoder};
use bstr::{ByteSlice, ByteVec, io::BufReadExt};
use futures::{FutureExt, StreamExt, TryStreamExt};
use harmonia_file_nar::{NarEvent, parse_nar};
use hyperscan::{Builder, DatabaseRef, Matching, StreamingDatabase, StreamingMode, pattern};
use tokio::{
    io::AsyncRead,
    signal::unix::{Signal, SignalKind},
    time::Instant,
};
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
        hyperscan::pattern! { r##"Electron/[0-9]*\.[0-9]*\.[0-9]*"##; SOM_LEFTMOST }
            .build()
            .unwrap();

    // Reqwest client shared with all tasks
    let ref client = reqwest::Client::new();

    // For diagnostics
    let ref total_processed = AtomicU64::new(0);

    // Process on a task-per-core setup where we
    // first pull the narinfo file, find the url for the nar archive,
    // then stream the nar archive, decompress the stream as it's streaming,
    // and then inspect the decompressed stream. We should not load a full archive
    // into memory.
    let mut found = futures::stream::iter(store_paths)
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

            // Pull the NAR down as an async stream
            let compressed_stream = match get_nar(client, url).await {
                Ok(compressed_stream) => compressed_stream,
                Err(err) => {
                    let _ = logging_tx
                        .send(Diagnostic::Error(
                            name.to_string(),
                            format!("nar failed: '{err}'"),
                        ))
                        .await;
                    return vec![];
                }
            };

            // Wrap in a decoder
            let decompressed_stream: Box<dyn AsyncRead> = match compression {
                Compression::Zstd => Box::new(ZstdDecoder::new(compressed_stream)),
                Compression::Xz => Box::new(XzDecoder::new(compressed_stream)),
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
            let decompressed_bytes = Box::into_pin(decompressed_stream);

            // Make sure this is incremented after we decode or else
            // we will add data we never actually processed
            let size = narinfo.get_nar_filesize();
            total_processed.fetch_add(size, Ordering::Relaxed);

            // Then stuff it into parse events. We only want to scan files so filter to those.
            // Then call the scanning function.
            let mut parse_events = pin!(parse_nar(decompressed_bytes));

            // Mark the store paths that are matched
            let mut nar_finds: Vec<PathBuf> = vec![];

            // Buffer keeping track of the current nix store path we are looking at.
            let mut current_path = PathBuf::from(name);

            loop {
                if let Ok(Some(event)) = parse_events.try_next().await {
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
                } else {
                    // TODO: Retry upon error
                    break;
                }
            }

            let _ = logging_tx.send(Diagnostic::Finish(name.to_string())).await;
            nar_finds
        })
        .buffer_unordered(std::thread::available_parallelism().unwrap().get())
        .fuse();

    // Remember, this is what actually drives the whole thing.
    // the call to collect runs the above processing
    let mut signals = get_signals();
    let signals = signals.iter_mut().map(|sig| Box::pin(sig.recv()));
    let mut signals = futures::future::select_all(signals).fuse();

    let start = Instant::now();
    let mut output = vec![];
    let mut total_paths = 0u64;

    loop {
        tokio::select! {
            biased;
            data = found.next() => {
                match data {
                    Some(data) => {
                        total_paths += 1;
                        if !data.is_empty() {
                            output.extend(data)
                        }
                    }
                    None => break,
                }
            },
            _ = &mut signals => break,
        }
    }

    // Final result
    let _ = logging_tx.send(Diagnostic::Result(output)).await;
    let _ = logging_worker.await; // Must await or else the process usually shuts down before the results are printed

    let duration = Instant::now() - start;
    eprintln!(
        r##"Data processed: {} MiB
Processing time: {:.1} sec
Total paths process: {} store paths
        "##,
        total_processed.load(Ordering::Relaxed) >> 20,
        duration.as_secs_f32(),
        total_paths
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

fn get_signals() -> [Signal; 5] {
    use tokio::signal::unix::signal;

    let alarm = signal(SignalKind::alarm()).unwrap();
    let hup = signal(SignalKind::hangup()).unwrap();
    let interrupt = signal(SignalKind::interrupt()).unwrap();
    let pipe = signal(SignalKind::pipe()).unwrap();
    let term = signal(SignalKind::terminate()).unwrap();

    [alarm, hup, interrupt, pipe, term]
}
