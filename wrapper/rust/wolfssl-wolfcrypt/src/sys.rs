/*
 * Suppress warnings for bindgen-generated bindings to wolfssl C library.
 */
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::ptr_offset_with_cast)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::useless_transmute)]
#![allow(dead_code)]
#![allow(improper_ctypes)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unnecessary_transmutes)]
#![allow(unsafe_op_in_unsafe_fn)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/* Include generated FIPS symbol aliases. */
include!(concat!(env!("OUT_DIR"), "/fips_aliases.rs"));

#[cfg(not(rsa_setrng))]
unsafe extern "C" {
    pub fn wc_RsaSetRNG(key: *mut RsaKey, rng: *mut WC_RNG) -> core::ffi::c_int;
}
