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
