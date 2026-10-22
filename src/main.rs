use std::pin::pin;

use async_compression::tokio::bufread::ZstdDecoder;
use bstr::{ByteSlice, ByteVec};
use futures::{AsyncRead, StreamExt, TryStreamExt};
use harmonia_file_nar::{NarEvent, parse_nar};
use reqwest::{Client, Response};
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

    let client = &reqwest::Client::new();

    let found = futures::stream::iter(store_paths)
        .map(|digest| async move {
            println!("{digest}\n");
            let narinfo = match get_narinfo(client, &digest).await {
                Ok(res) => res.text().await.unwrap(),
                Err(_) => return vec![],
            };
            println!("{narinfo}\n");

            // Get the nar path
            let url = get_nar_url(&narinfo);
            println!("url: {url}");

            // Get the compression type
            let compression = get_nar_compression(&narinfo);
            println!("comp: {compression}");
            assert_eq!(compression, "zstd", "Only supports zstd right now");

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

            let mut nar_finds: Vec<usize> = vec![];

            while let Some(event) = parse_events.try_next().await.unwrap() {
                if let NarEvent::File {
                    name,
                    executable,
                    reader,
                    size,
                } = event
                {
                    if let Some((_, found)) =
                        scanner(name, executable, size, Box::new(reader)).await
                    {
                        nar_finds.extend_from_slice(&found);
                    }
                }
            }

            return nar_finds;
        })
        .buffer_unordered(8);

    let output: Vec<_> = found.collect().await;
    println!("found: {:?}", output);
    Ok(())
}

// Yeah scan that file. Do ur stuff.
async fn scanner(
    name: Bytes,
    executable: bool,
    _: u64,
    reader: Box<dyn tokio::io::AsyncBufRead>,
) -> Option<(Bytes, Vec<usize>)> {
    if !executable {
        return None;
    }

    let mut stream = ReaderStream::new(Box::into_pin(reader));

    let mut found = Vec::new();

    while let Some(chunk) = stream.next().await {
        for (index, &byte) in chunk.iter().flatten().enumerate() {
            if byte == 0u8 {
                found.push(index)
            }
            // Regex automata
            // state = pikevm.next_state(state, byte);
            //
            // if pikevm.is_match_stare(state) {
            //    // do something
            // }
        }
    }

    if !found.is_empty() {
        Some((name, found))
    } else {
        None
    }
}
