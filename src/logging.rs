use std::path::PathBuf;

use tokio::{
    io::AsyncWriteExt,
    sync::mpsc::{self, Sender},
    task::JoinHandle,
};

pub enum Diagnostic {
    Start(String),
    Finish(String, Vec<PathBuf>),
    Error(String, String),
}

pub fn get_worker() -> (JoinHandle<()>, Sender<Diagnostic>) {
    // For sending stuff to stderr
    let (stdout_tx, mut stdout_rx) = mpsc::channel::<Diagnostic>(16);

    // Little worker task that just writes stuff to stdout in a coherent manner
    let stdout_worker = tokio::spawn(async move {
        let mut output = tokio::io::stdout();
        while let Some(mess) = stdout_rx.recv().await {
            let jsonl = match mess {
                Diagnostic::Start(name) => {
                    // { message: "start", path: "..." }
                    format!(r##"{{"message": "start", "path": "{}"}}"##, name)
                }
                Diagnostic::Finish(name, paths) => {
                    // { message: "start", path: "..." }
                    format!(
                        r##"{{"message": "finish", "path": "{}", "matches": {:?}}}"##,
                        name, paths
                    )
                }
                Diagnostic::Error(name, message) => {
                    // { message: "error", "path": "...", "error": "..." }
                    format!(
                        r##"{{"message": "error", "path": "{}", "error": "{}"}}"##,
                        name, message
                    )
                }
            };
            let _ = output.write_all((jsonl + "\n").as_bytes()).await;
        }
    });

    (stdout_worker, stdout_tx)
}
