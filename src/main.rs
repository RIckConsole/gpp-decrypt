use openssl::symm::{decrypt, Cipher};
use read_input::prelude::*;

const LOGO: &str = include_str!("../logo.txt");

fn main() {
    println!("{}", LOGO);

    let data: Vec<u8> = loop {
        print!("\nInput the cpassword: ");
        let mut input: String = input().get();

        // pad the string
        input.extend(
            // creates an iterator that returns a '=' per iteration
            (0..4 - (input.len() % 4)).map(|_| '='));

        // decode it, if it fails print a friendly error message
        match base64::decode(input) {
            Ok(data) => break data,
            _ => println!("error: input is not valid base64"),
        }
    };

    match gpp_decrypt(&data) {
        Some(output) => println!("result: {}", output),
        None => println!("error: failed to decrypt {:?}", &data)
    }
}

const INIT_V: &[u8; 16] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const KEY: &[u8; 32] = b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b";

/// Decrypts the provided Group Policy Preference cpassword. Returns `None` if
/// decryption fails.
fn gpp_decrypt(data: &[u8]) -> Option<String> {
    decrypt(Cipher::aes_256_cbc(), KEY, Some(INIT_V), data)
        .ok()
        .and_then(|dec| String::from_utf8(dec).ok())
}
