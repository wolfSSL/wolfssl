#![cfg(fips)]

use crate::sys;

/// Enables or disables the ability to read private key data in FIPS mode.
///
/// In FIPS mode, private keys are protected and cannot be read by default.
/// This function allows temporarily enabling private key reads for operations
/// that require access to the raw key material, such as key export or backup.
///
/// # Arguments
///
/// * `enabled` - Set to `1` to enable private key reads, or `0` to disable.
///
/// # Returns
///
/// * `Ok(())` - The operation succeeded.
/// * `Err(i32)` - The operation failed, returning the wolfSSL error code.
///
/// # Note
///
/// This function applies to all key types (`WC_KEYTYPE_ALL`). Private key
/// reading should be disabled again after the required operation is complete
/// to maintain FIPS compliance.
pub fn set_private_key_read_enable(enabled: i32) -> Result<(), i32> {
    let rc = unsafe {
        sys::wolfCrypt_SetPrivateKeyReadEnable_fips(enabled, sys::wc_KeyType_WC_KEYTYPE_ALL)
    };
    if rc != 0 {
        Err(rc)
    } else {
        Ok(())
    }
}

/// Enables private key reads on the current thread until dropped.
///
/// Reads are counted per thread, so guards can be nested.
pub struct PrivateKeyRead {
    _private: (),
}

impl PrivateKeyRead {
    /// Returns the guard, or an Err containing the wolfSSL library return code.
    pub fn enable() -> Result<Self, i32> {
        set_private_key_read_enable(1)?;
        Ok(PrivateKeyRead { _private: () })
    }
}

impl Drop for PrivateKeyRead {
    fn drop(&mut self) {
        // Only fails for a bad key type.
        let _ = set_private_key_read_enable(0);
    }
}

/// Runs all FIPS self tests (CASTs) once, so concurrent first use of an
/// algorithm can't fail while its self test is running.
///
/// Later and concurrent calls wait for the first and return its result. A
/// positive Err is the number of failed self tests.
pub fn run_all_self_tests() -> Result<(), i32> {
    use core::sync::atomic::{AtomicI32, AtomicU8, Ordering};

    const NOT_RUN: u8 = 0;
    const RUNNING: u8 = 1;
    const DONE: u8 = 2;
    static STATE: AtomicU8 = AtomicU8::new(NOT_RUN);
    static RESULT: AtomicI32 = AtomicI32::new(0);

    if STATE
        .compare_exchange(NOT_RUN, RUNNING, Ordering::Acquire, Ordering::Acquire)
        .is_ok()
    {
        // Some self tests need the RNG, which has no seed callback yet.
        let mut rc = unsafe { sys::wc_SetSeed_Cb_fips(Some(sys::wc_GenerateSeed)) };
        if rc == 0 {
            rc = unsafe { sys::wc_RunAllCast_fips() };
        }
        RESULT.store(rc, Ordering::Relaxed);
        STATE.store(DONE, Ordering::Release);
    } else {
        while STATE.load(Ordering::Acquire) != DONE {
            core::hint::spin_loop();
        }
    }

    match RESULT.load(Ordering::Relaxed) {
        0 => Ok(()),
        rc => Err(rc),
    }
}
