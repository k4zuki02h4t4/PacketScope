//! End-to-end TLS decryption test against streams captured from a real
//! OpenSSL session (via a tee proxy). Driven by env vars so it stays inert
//! in normal CI: NW_TEST_UP, NW_TEST_DOWN, NW_TEST_KEYS, NW_TEST_EXPECT_UP,
//! NW_TEST_EXPECT_DOWN.
use netwatch::tls::{try_decrypt, KeyLog};

#[test]
fn decrypt_captured_session() {
    let (Ok(up_p), Ok(down_p), Ok(keys_p)) = (
        std::env::var("NW_TEST_UP"),
        std::env::var("NW_TEST_DOWN"),
        std::env::var("NW_TEST_KEYS"),
    ) else {
        eprintln!("skipped: NW_TEST_* not set");
        return;
    };
    let up = std::fs::read(up_p).unwrap();
    let down = std::fs::read(down_p).unwrap();
    let mut keys = KeyLog::new();
    keys.refresh(std::path::Path::new(&keys_p));
    assert!(keys.entries() > 0, "no keys loaded");
    let dec = try_decrypt(&up, &down, &mut keys).expect("decryption failed");
    let up_text = String::from_utf8_lossy(&dec.up).into_owned();
    let down_text = String::from_utf8_lossy(&dec.down).into_owned();
    println!("--- decrypted up ---\n{up_text}\n--- decrypted down (first 400) ---\n{}", &down_text[..down_text.len().min(400)]);
    if let Ok(m) = std::env::var("NW_TEST_EXPECT_UP") {
        assert!(up_text.contains(&m), "up marker {m:?} not found");
    }
    if let Ok(m) = std::env::var("NW_TEST_EXPECT_DOWN") {
        assert!(down_text.contains(&m), "down marker {m:?} not found");
    }
}
