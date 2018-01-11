use std::fs::File;
use std::env;
use std::path::Path;
use std::process::exit;
use std::process::Command;
use std::io::{BufRead, BufReader};

fn main() {
    let path = match env::args().nth(1) {
        Some(v) => {
            if !Path::new(&v).exists() {
                println!("file '{}' does not exists", v);
                exit(1);
            } else {
                v
            }
        },
        None => {
            println!("Usage: ./test <path>");
            exit(1);
        }
    };

    let file = match File::open(&path) {
        Ok(v) => v,
        Err(e) => {
            panic!(e)
        }
    };

    let mut r = BufReader::new(file);
    let mut expected = vec![];
    let _ = r.read_until(b'(', &mut vec![]);
    let _ = r.read_until(b')', &mut expected);
    let expected = ::std::str::from_utf8(&expected[0..expected.len()-1]).expect("outupt is not valid utf8").trim();

    print!("{} ", path);
    let cmd = Command::new("sh").arg("-c").arg(format!("cat 00-core.ft {} | ./test", path)).output().expect("execution failed");
    let status = cmd.status;
    if !status.success() {
        println!("[31mERROR[0m");
        if let Some(code) = status.code() {
            println!("exec failed, code: {}", code);
        }
        let err = cmd.stderr;
        let err = ::std::str::from_utf8(&err).expect("outupt is not valid utf8");
        println!("error: {}", err);
        return;
    }
    let out = cmd.stdout;
    let result = ::std::str::from_utf8(&out).expect("outupt is not valid utf8");
    if result == expected {
        println!("[32mOK[0m");
    } else {
        println!("[31mERROR[0m");
        println!("expected: '{}'", expected);
        println!("but given: '{}'", result);
    }
}
