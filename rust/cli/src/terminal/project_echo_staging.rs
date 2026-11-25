// Standalone, non-sensitive project fixture. No filesystem, environment,
// credential, network, subprocess, shell, ACL or Bridge database operations.
// This executable is built only for privately staged process parity.
use std::io::{self, BufRead, Write};
use std::time::Duration;

fn main() {
    println!("READY public-echo-v1");
    let _=io::stdout().flush();
    let stdin=io::stdin();
    for line in stdin.lock().lines().take(4) {
        let Ok(line)=line else {break;};
        let parsed=line.strip_prefix("{\"delay_ms\":")
            .and_then(|suffix|suffix.split_once(",\"operation\":\"echo\",\"phrase\":\""))
            .and_then(|(delay,rest)|rest.strip_suffix("\"}").map(|phrase|(delay,phrase)));
        let Some((delay,phrase))=parsed else {
            println!("DENIED invalid public frame");
            let _=io::stdout().flush();
            continue;
        };
        let Ok(ms)=delay.parse::<u64>() else {println!("DENIED delay");continue;};
        if ms>3000 || phrase.is_empty() || phrase.len()>96
            || !phrase.chars().all(|c|c.is_ascii_alphanumeric()||matches!(c,' '|'_'|'-')) {
            println!("DENIED public values");
            let _=io::stdout().flush();
            continue;
        }
        println!("ACCEPTED");
        let _=io::stdout().flush();
        std::thread::sleep(Duration::from_millis(ms));
        println!("RESPONSE {}",phrase);
        let _=io::stdout().flush();
    }
}
