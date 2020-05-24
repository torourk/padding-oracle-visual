use colored::*;
use std::fmt::Write;

/// Generates a random string of length len
fn random_string(len: usize) -> String {
    std::iter::repeat(())
        .map(|()| rand::Rng::sample(&mut rand::thread_rng(), rand::distributions::Alphanumeric))
        .take(len)
        .collect()
}

/// Writes an incomplete block using random text for hacker aesthetic.
/// This also allows us to represent ciphertext values that are not valid ASCII.
fn write_incomplete_block(line: &mut String) {
    write!(line, "{}", random_string(16).blue().bold()).unwrap();
}

fn write_in_progress_block(line: &mut String, block: &[u8], bytes_broken: usize, padded: bool) {
    let padded_bytes = if padded {
        Some(block[15] as usize)
    } else {
        None
    };

    // Creates the random text for the unknown bytes
    let unknown_bytes = 16 - bytes_broken;
    let unknown_spaces = random_string(unknown_bytes.max(1) - 1).green().bold();

    let divider = if bytes_broken < 16 {
        "|".white().bold().to_string()
    } else {
        "".to_string()
    };

    let known_bytes = &block[unknown_bytes..(16 - padded_bytes.unwrap_or(0))];
    let known_str = std::str::from_utf8(known_bytes).unwrap();

    let padded_str = if let Some(bytes) = padded_bytes {
        let mut out = String::new();
        for _ in 0..bytes {
            write!(out, " {:02x?}", bytes).unwrap();
        }
        out
    } else {
        "".to_string()
    };

    write!(
        line,
        "{}{}{}{}",
        unknown_spaces,
        divider,
        known_str.bold(),
        padded_str.blue().bold()
    )
    .unwrap();
}

fn write_finished_block(line: &mut String, block: &[u8], padded: bool) {
    let padded_bytes = if padded {
        Some(block[15] as usize)
    } else {
        None
    };

    let block_bytes = &block[..(16 - padded_bytes.unwrap_or(0))];
    let block_str = std::str::from_utf8(block_bytes).unwrap();

    let padded_str = if let Some(bytes) = padded_bytes {
        let mut out = String::new();
        for _ in 0..bytes {
            write!(out, " {:02x?}", bytes).unwrap();
        }
        out
    } else {
        "".to_string()
    };

    write!(line, "{}{}", block_str.bold(), padded_str.blue().bold()).unwrap();
}

/// Rewrites the output line using various parameters
pub fn write_line(plaintext: &[u8], m2: &[u8], m2_bytes_broken: usize, num_cipher_blocks: usize) {
    let num_cipher_blocks = num_cipher_blocks - 1;

    let mut line = String::new();

    let plaintext_blocks = plaintext.len() / 16;
    let incompleted_blocks = num_cipher_blocks - plaintext_blocks - 1;

    for block_i in 0..num_cipher_blocks {
        if block_i > 0 {
            write!(line, "|").unwrap();
        }

        if block_i < incompleted_blocks {
            write_incomplete_block(&mut line);
        } else if block_i < incompleted_blocks + 1 {
            let padded = block_i >= num_cipher_blocks - 1;
            write_in_progress_block(&mut line, m2, m2_bytes_broken, padded);
        } else {
            let padded = block_i >= num_cipher_blocks - 1;
            let plaintext_index = block_i - incompleted_blocks - 1;
            let text_slice = &plaintext[(plaintext_index * 16)..(plaintext_index * 16 + 16)];
            write_finished_block(&mut line, text_slice, padded);
        }
    }

    print!("\r[{}]", line);
    std::io::Write::flush(&mut std::io::stdout()).unwrap();

    // This slows down the program for a better viewing experience
    std::thread::sleep(std::time::Duration::from_millis(100));
}
