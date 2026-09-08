// Compiled by the integration test as a portable, standalone fake executable.
use std::io::{Read, Write};

fn main() {
    let dir = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let mode = std::fs::read_to_string(dir.join("mode")).unwrap();
    let args: Vec<_> = std::env::args().skip(1).collect();
    std::fs::write(dir.join("argv"), args.join("\n")).unwrap();
    assert_eq!(args[0], "--pure");
    let mut stdin = Vec::new();
    std::io::stdin().read_to_end(&mut stdin).unwrap();
    assert!(stdin.is_empty());
    std::fs::write(dir.join("stdin-closed"), b"yes").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std::fs::write(
        dir.join("address"),
        listener.local_addr().unwrap().to_string(),
    )
    .unwrap();
    std::fs::write(dir.join("ready"), b"yes").unwrap();
    std::fs::write(dir.join("pid"), std::process::id().to_string()).unwrap();
    if mode.trim() == "stderr-exact" {
        std::io::stderr().write_all(&[b'x'; 8192]).unwrap();
    }
    match mode.trim() {
        "timeout" => loop {
            std::thread::park();
        },
        "stdout" => loop {
            std::io::stdout().write_all(&[b'x'; 4096]).unwrap();
        },
        "stderr" => loop {
            std::io::stderr().write_all(&[b'x'; 4096]).unwrap();
        },
        "both" => loop {
            std::io::stdout().write_all(&[b'x'; 4096]).unwrap();
            std::io::stderr().write_all(&[b'x'; 4096]).unwrap();
        },
        "nonzero" => {
            eprintln!("SYNTHETIC_PRIVATE_STDERR");
            std::process::exit(19);
        }
        _ => {
            let filename = if args.get(1).map(String::as_str) == Some("session") {
                assert_eq!(args[2..6], ["list", "--format", "json", "--max-count"]);
                assert_eq!(args.len(), 7);
                assert!((1..=256).contains(&args[6].parse::<usize>().unwrap()));
                std::fs::write(dir.join("listing-argv"), args.join("\n")).unwrap();
                "listing.json"
            } else {
                assert_eq!(args[1], "export");
                assert_eq!(args[3], "--sanitize");
                assert_eq!(args.len(), 4);
                "export.json"
            };
            std::io::stdout()
                .write_all(&std::fs::read(dir.join(filename)).unwrap())
                .unwrap();
        }
    }
}
