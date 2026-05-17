//! tord-query — CLI for the `/run/tord.sock` control socket.
//!
//! Mirrors `dnsd-query`. Installed on the appliance as
//! `imp-tord-query`. Usage: `tord-query [command]` (default
//! `status`); commands: `status`, `stats`, `reload`, `ping`. The
//! socket path can be overridden with `TORD_SOCKET`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "status".into());
    let path = std::env::var("TORD_SOCKET").unwrap_or_else(|_| tord::control::DEFAULT_SOCKET.into());

    match query(&path, &cmd) {
        Ok(resp) => {
            print!("{resp}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("tord-query: {e}");
            ExitCode::FAILURE
        }
    }
}

fn query(path: &str, cmd: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(path)?;
    writeln!(stream, "{cmd}")?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp)?;
    Ok(resp)
}
