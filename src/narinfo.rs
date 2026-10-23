use reqwest::{Client, Response};

use crate::CACHE_SITE;

pub async fn get_narinfo(client: &Client, digest: &str) -> Result<Response, reqwest::Error> {
    // https://cache.nixos.org/005q6mj9lbz7vazzs6j2d68h8gda97ic.narinfo
    client
        .get(CACHE_SITE.to_string() + digest + ".narinfo")
        .send()
        .await
}

#[repr(transparent)]
pub struct NarInfo<'text>(&'text str);

impl<'text> NarInfo<'text> {
    pub fn new(data: &'text str) -> Self {
        Self(data)
    }

    pub fn get_nar_url(&self) -> &str {
        self.0
            .lines()
            .nth(1)
            .unwrap()
            .strip_prefix("URL: ")
            .unwrap()
    }

    pub fn get_nar_compression(&self) -> &str {
        self.0
            .lines()
            .nth(2)
            .unwrap()
            .strip_prefix("Compression: ")
            .unwrap()
    }

    pub fn get_nar_name(&self) -> &str {
        self.0
            .lines()
            .next()
            .unwrap()
            .strip_prefix("StorePath: ")
            .unwrap()
    }

    pub fn get_nar_filesize(&self) -> &str {
        self.0
            .lines()
            .nth(4)
            .unwrap()
            .strip_prefix("FileSize: ")
            .unwrap()
    }
}

#[cfg(test)]
mod test {
    use crate::narinfo::NarInfo;

    const NARINFO: &str = include_str!("../test-data/narinfo.txt");

    #[test]
    fn get_narinfo_data() {
        let nar = NarInfo::new(NARINFO);

        assert_eq!(
            nar.get_nar_url(),
            "nar/15wqblfjqn4v1hd7jgk4759pr1vgs7c9gkwiniy036hzcr06fgys.nar.zst"
        );
        assert_eq!(nar.get_nar_compression(), "zstd");
        assert_eq!(
            nar.get_nar_name(),
            "/nix/store/005q6mj9lbz7vazzs6j2d68h8gda97ic-fuzzel-1.15.0"
        );
        assert_eq!(nar.get_nar_filesize(), "187461");
    }
}
