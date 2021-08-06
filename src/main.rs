use read_input::prelude::*;
use base64::{decode};
use openssl::symm::{Cipher, decrypt};


fn main() {
    print!("Input the cpassword: ");
    let input = input::<String>().get(); 
    gpp_decrypt(input);
}

fn gpp_decrypt(input: String) {
    let mut encrypted_data = input;
    let repeat_times = 4 - (encrypted_data.len() % 4);
    let padding: String = "=".to_string().repeat(repeat_times); 
    let _ = encrypted_data.push_str(&padding); 
    let decoded = decode(encrypted_data);
    let key = b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b";
    let aes = Cipher::aes_256_cbc();
    let iv= b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"; 
    let decrypted  = decrypt(aes, key, Some(iv), &decoded.unwrap());
    let s = match String::from_utf8(decrypted.unwrap()) { //convert to readable text
        Ok(v) => v,
        Err(_e) => panic!("Invalid UTF-8 Sequence"),
    };
    println!("Result: {}", s);

}
