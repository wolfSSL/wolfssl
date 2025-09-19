use wolfssl::wolfcrypt::random::RNG;

// Test that RNG::new() returns successfully and that drop() does not panic.
#[test]
fn test_rng_new_and_drop() {
    let _rng = RNG::new().expect("Failed to create RNG");
}

// Test that RNG::new_with_nonce() returns successfully and that drop() does
// not panic.
#[test]
fn test_rng_new_with_nonce_and_drop() {
    let mut nonce = [1, 2, 3, 4];
    let _rng = RNG::new_with_nonce(&mut nonce).expect("Failed to create RNG");
}

// Test that generate_byte() returns random values.
#[test]
fn test_rng_generate_byte() {
    // Since a single 0x00 or 0xFF could occur occasionally, we'll combine four
    // bytes into a u32 and make sure they aren't all 0x00 or all 0xFF.
    let mut rng = RNG::new().expect("Failed to create RNG");
    let mut v: u32 = 0;
    for _i in 0..4 {
        let byte = rng.generate_byte().expect("Failed to generate a single byte");
        v = (v << 8) | (byte as u32);
    }
    assert_ne!(v, 0u32);
    assert_ne!(v, 0xFFFF_FFFFu32);
}

// Test that generate_block works for a slice of u8.
#[test]
fn test_rng_generate_block_u8() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let mut buffer = [0u8; 32];
    rng.generate_block(&mut buffer).expect("Failed to generate a block of bytes");

    // Check if the buffer has been modified from its initial state.
    let all_zeros = [0u8; 32];
    assert_ne!(buffer, all_zeros);
}

// Test that generate_block works for a slice of u32.
#[test]
fn test_rng_generate_block_u32() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let mut buffer = [0u32; 8];
    rng.generate_block(&mut buffer).expect("Failed to generate a block of u32");

    // Check if the buffer has been modified.
    let all_zeros = [0u32; 8];
    assert_ne!(buffer, all_zeros);
    // Check that the last u32 is populated so the size of the buffer was
    // calculated properly.
    assert_ne!(buffer[buffer.len() - 1], 0u32);
    assert_ne!(buffer[buffer.len() - 1], 0xFFFF_FFFFu32);
}
