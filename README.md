[Documentation](https://http://peterreid.github.io/chacha)

# Adding a Dependency

If you are using a stable Rust build:

    [dependencies]
    chacha = "0.1.0"

If you need maximum performance, using a nightly Rust build:

    [dependencies.chacha]
    version = "0.1.0"
    features = ["nightly"]


# Example

    extern crate chacha;

    use chacha::{ChaCha, KeyStream};

    fn main() {
        let secret_key = [
            0x29, 0xfa, 0x35, 0x60, 0x88, 0x45, 0xc6, 0xf9, 
            0xd8, 0xfe, 0x65, 0xe3, 0x22, 0x0e, 0x5b, 0x05, 
            0x03, 0x4a, 0xa0, 0x9f, 0x9e, 0x27, 0xad, 0x0f, 
            0x6c, 0x90, 0xa5, 0x73, 0xa8, 0x10, 0xe4, 0x94, 
        ];
        let nonce = [0u8; 8];
        let mut stream = ChaCha::new_chacha20(&secret_key, &nonce);

        let mut buffer = *b"abcdef";
        println!("Plaintext = {:?}", buffer);
        stream.xor_read(&mut buffer[..]).expect("hit end of stream far too soon");
        println!("Ciphertext = {:?}", buffer);
    }
