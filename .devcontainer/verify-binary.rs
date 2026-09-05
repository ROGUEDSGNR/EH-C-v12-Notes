use std::{env, fs, process};

fn main() {
    let mut args = env::args().skip(1);
    let binary_path = args.next().unwrap_or_default();
    if binary_path.is_empty() {
        eprintln!("usage: verify-binary <binary> <forbidden-blob>...");
        process::exit(2);
    }
    let binary = fs::read(&binary_path).unwrap_or_else(|error| {
        eprintln!("cannot read {binary_path}: {error}");
        process::exit(2);
    });
    let mut checked = 0usize;
    for path in args {
        let forbidden = fs::read(&path).unwrap_or_else(|error| {
            eprintln!("cannot read {path}: {error}");
            process::exit(2);
        });
        if forbidden.is_empty() {
            eprintln!("forbidden blob is empty: {path}");
            process::exit(2);
        }
        checked += 1;
        if binary.windows(forbidden.len()).any(|window| window == forbidden) {
            eprintln!("forbidden upstream blob is embedded in {binary_path}: {path}");
            process::exit(1);
        }
    }
    if checked != 11 {
        eprintln!("expected 11 forbidden upstream blobs, checked {checked}");
        process::exit(2);
    }
    println!("Verified absence of 11 upstream browser/template blobs.");
}
