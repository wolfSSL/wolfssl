#![cfg(random)]

use wolfssl_wolfcrypt::random::RNG;

// Test that RNG::new() returns successfully and that drop() does not panic.
#[test]
fn test_rng_new_and_drop() {
    let _rng = RNG::new().expect("Failed to create RNG");
}

// Test that RNG::new_ex() returns successfully and that drop() does not panic.
#[test]
fn test_rng_new_ex_and_drop() {
    let _rng = RNG::new_ex(None, None).expect("Failed to create RNG");
}

// Test that RNG::new_with_nonce() returns successfully and that drop() does
// not panic.
#[test]
fn test_rng_new_with_nonce_and_drop() {
    let mut nonce = [1, 2, 3, 4];
    let _rng = RNG::new_with_nonce(&mut nonce).expect("Failed to create RNG");
}

// Test that RNG::new_with_nonce_ex() returns successfully and that drop() does
// not panic.
#[test]
fn test_rng_new_with_nonce_ex_and_drop() {
    let mut nonce = [1, 2, 3, 4];
    let _rng = RNG::new_with_nonce_ex(&mut nonce, None, None).expect("Failed to create RNG");
}

#[test]
#[cfg(random_hashdrbg)]
fn test_health_test() {
    let nonce = [99u8, 88, 77, 66];
    let seed_a = [42u8, 33, 55, 88];
    let seed_b = [45u8, 10, 20, 30];
    let mut output = [0u8; 128];
    RNG::health_test(Some(&nonce), &seed_a, Some(&seed_b), &mut output).expect("Error with health_test()");
}

#[test]
#[cfg(random_hashdrbg)]
fn test_test_seed() {
    let seed = [42u8, 33, 55, 88];
    RNG::test_seed(&seed).expect("Error with test_seed()");
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

#[test]
#[cfg(random_hashdrbg)]
fn test_rng_reseed() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let seed = [1u8, 2, 3, 4];
    rng.reseed(&seed).expect("Error with reseed()");
}

#[test]
#[cfg(feature = "rand_core")]
fn test_rng_rand_core_fill_bytes() {
    use rand_core::Rng;
    let mut rng = RNG::new().expect("Failed to create RNG");
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    assert_ne!(buf, [0u8; 32]);
}

#[test]
#[cfg(feature = "rand_core")]
fn test_rng_rand_core_try_fill_bytes() {
    use rand_core::TryRng;
    let mut rng = RNG::new().expect("Failed to create RNG");
    let mut buf = [0u8; 32];
    rng.try_fill_bytes(&mut buf).expect("Failed to try_fill_bytes");
    assert_ne!(buf, [0u8; 32]);
}

#[test]
#[cfg(feature = "rand_core")]
fn test_rng_rand_core_next_u32() {
    use rand_core::Rng;
    let mut rng = RNG::new().expect("Failed to create RNG");
    // Generate several values and verify they aren't all zero
    let v: u64 = (0..4).map(|_| rng.next_u32() as u64).sum();
    assert_ne!(v, 0);
}

#[test]
#[cfg(feature = "rand_core")]
fn test_rng_rand_core_next_u64() {
    use rand_core::Rng;
    let mut rng = RNG::new().expect("Failed to create RNG");
    // Generate two values and verify they aren't all ones
    let v1 = rng.next_u64();
    let v2 = rng.next_u64();
    assert_ne!(v1 & v2, u64::MAX);
}

#[test]
#[cfg(feature = "rand_core")]
fn test_rng_is_crypto_rng() {
    use rand_core::CryptoRng;
    fn requires_crypto_rng<R: CryptoRng>(_: &R) {}
    let rng = RNG::new().expect("Failed to create RNG");
    requires_crypto_rng(&rng);
}
