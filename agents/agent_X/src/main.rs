use std::fs::{File, OpenOptions};
use std::io::{Write, Read};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;
use chrono::Local;

fn main() {
    println!("I can hoard memory, but I am just spitting out files");

    // Write files 11 to 22
    for i in 11..=22 {
        let filename = format!("file{:02}.txt", i);
        let now = Local::now();
        let timestamp = now.format("%Y-%m.%d_%H%M").to_string();

        let mut file = File::create(&filename).expect("Failed to create file");
        writeln!(file, "{}", timestamp).expect("Failed to write timestamp");
    }

    // Randomly choose a file from 11 to 22
    let random_index = rand::thread_rng().gen_range(11..=22);
    let random_filename = format!("file{:02}.txt", random_index);

    // Read the contents
    let mut file = OpenOptions::new()
        .read(true)
        .open(&random_filename)
        .expect("Failed to open file");

    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Failed to read file");

    println!("read file {} and the contents is {}", random_filename, contents.trim());
}
