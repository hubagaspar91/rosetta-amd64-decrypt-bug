// Standalone test that pinpoints where `ring`'s ChaCha20-Poly1305 goes wrong,
// with zero dependencies beyond the crypto crates.
//
//   * RustCrypto  (chacha20poly1305) — portable Rust + CPU intrinsics
//   * ring        (BoringSSL-derived, hand-written x86-64 assembly)
//
// Both are validated against published vectors (RFC 8439, and Google's Wycheproof
// suite), then compared byte-for-byte against each other across a dense range of
// message sizes. Because AEAD is deterministic and RustCrypto is validated, any size
// where `ring` differs is `ring` computing the WRONG result. On amd64 under Rosetta 2
// on an Apple M5 that begins at 512 bytes; everywhere else the two always agree.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use hex_literal::hex;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

mod wycheproof;

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex_string = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex_string.push_str(&format!("{byte:02x}"));
    }
    hex_string
}

fn report_known_answer(test_name: &str, actual: &[u8], expected: &[u8], failure_count: &mut u32) {
    if actual == expected {
        println!("  PASS  {test_name}");
    } else {
        *failure_count += 1;
        println!("  FAIL  {test_name}");
        println!("        expected: {}", bytes_to_hex(expected));
        println!("        actual:   {}", bytes_to_hex(actual));
    }
}

// A deterministic filler message of the requested length (content is irrelevant to
// the bug; only the length matters, so a simple repeating pattern is fine).
fn filler_message(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

// "seal" = encrypt the plaintext and append the 16-byte authentication tag.
fn rustcrypto_chacha20poly1305_seal(key: &[u8], nonce: [u8; 12], associated_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new_from_slice(key)
        .unwrap()
        .encrypt(ChaChaNonce::from_slice(&nonce), Payload { msg: plaintext, aad: associated_data })
        .unwrap()
}

fn ring_chacha20poly1305_seal(key: &[u8], nonce: [u8; 12], associated_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let sealing_key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).unwrap());
    let mut output_buffer = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(associated_data), &mut output_buffer)
        .unwrap();
    output_buffer
}

fn main() {
    println!("=== ring vs RustCrypto ChaCha20-Poly1305 — known-answer + size-threshold sweep ===");
    println!("arch = {}", std::env::consts::ARCH);
    let mut known_answer_failures = 0u32;

    // 1a) Small published vector (RFC 8439 §2.8.2) — both implementations should pass.
    println!("\n--- published known-answer vector: SMALL input, 114 B (RFC 8439) ---");
    {
        let key = hex!("808182838485868788898a8b8c8d8e8f 909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; 12] = hex!("070000004041424344454647");
        let associated_data = hex!("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut expected_output = hex!(
            "d31a8d34648e60db7b86afbc53ef7ec2 a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b 1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58 fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b 6116"
        )
        .to_vec();
        expected_output.extend_from_slice(&hex!("1ae10b594f09e26a7e902ecbd0600691"));
        report_known_answer(
            "RustCrypto (RFC 8439, 114B)",
            &rustcrypto_chacha20poly1305_seal(&key, nonce, &associated_data, plaintext),
            &expected_output,
            &mut known_answer_failures,
        );
        report_known_answer(
            "ring       (RFC 8439, 114B)",
            &ring_chacha20poly1305_seal(&key, nonce, &associated_data, plaintext),
            &expected_output,
            &mut known_answer_failures,
        );
    }

    // 1b) A LARGE published vector (Google Wycheproof, 513-byte plaintext). Same kind
    //     of check, but at a size in ring's failing range: ring simply fails to
    //     reproduce the published bytes, so no cross-implementation reasoning is needed.
    println!("\n--- published known-answer vector: LARGE input, 513 B (Google Wycheproof tcId 90) ---");
    {
        report_known_answer(
            "RustCrypto (Wycheproof tcId 90, 513B)",
            &rustcrypto_chacha20poly1305_seal(&wycheproof::KEY, wycheproof::NONCE, wycheproof::ASSOCIATED_DATA, &wycheproof::PLAINTEXT),
            &wycheproof::EXPECTED_CIPHERTEXT_AND_TAG,
            &mut known_answer_failures,
        );
        report_known_answer(
            "ring       (Wycheproof tcId 90, 513B)",
            &ring_chacha20poly1305_seal(&wycheproof::KEY, wycheproof::NONCE, wycheproof::ASSOCIATED_DATA, &wycheproof::PLAINTEXT),
            &wycheproof::EXPECTED_CIPHERTEXT_AND_TAG,
            &mut known_answer_failures,
        );
    }

    // 2) Byte-for-byte ring-vs-RustCrypto sweep across message sizes. RustCrypto is
    //    the reference; any mismatch is `ring` computing the wrong output at that size.
    let sweep_key = [0x42u8; 32];
    let sweep_nonce = [7u8; 12];
    let no_associated_data: &[u8] = b"";
    // 64-byte steps up to 4 KB (a ChaCha20 block is 64 bytes), plus a couple beyond.
    let mut message_sizes: Vec<usize> = (1..=64).map(|block_count| block_count * 64).collect();
    message_sizes.push(6144);
    message_sizes.push(8192);

    println!("\n--- ring vs RustCrypto by message size ---");
    let mut first_mismatch_size: Option<usize> = None;
    let mut mismatching_sizes: Vec<usize> = Vec::new();
    for &message_size in &message_sizes {
        let plaintext = filler_message(message_size);
        let rustcrypto_output = rustcrypto_chacha20poly1305_seal(&sweep_key, sweep_nonce, no_associated_data, &plaintext);
        let ring_output = ring_chacha20poly1305_seal(&sweep_key, sweep_nonce, no_associated_data, &plaintext);
        if rustcrypto_output != ring_output {
            first_mismatch_size.get_or_insert(message_size);
            mismatching_sizes.push(message_size);
        }
    }
    match first_mismatch_size {
        None => println!("  ring matches RustCrypto at ALL {} sizes (64B..8192B)", message_sizes.len()),
        Some(size) => {
            println!("  FIRST MISMATCH at {size} bytes");
            println!("  mismatching sizes ({}): {:?}", mismatching_sizes.len(), mismatching_sizes);
            let matching_sizes: Vec<usize> =
                message_sizes.iter().copied().filter(|size| !mismatching_sizes.contains(size)).collect();
            println!("  still-matching sizes ({}): {:?}", matching_sizes.len(), matching_sizes);
        }
    }

    if known_answer_failures > 0 {
        std::process::exit(1);
    }
}
