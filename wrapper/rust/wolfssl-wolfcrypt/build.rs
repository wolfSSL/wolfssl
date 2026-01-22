extern crate bindgen;

use regex::Regex;
use std::env;
use std::fs;
use std::io::{self, Read, Result};
use std::path::{Path,PathBuf};

/// Perform crate build.
fn main() {
    if let Err(e) = run_build() {
        eprintln!("Build failed: {}", e);
        std::process::exit(1);
    }
}

/// Perform all build steps.
///
/// Returns `Ok(())` if successful, or an error if any step fails.
fn run_build() -> Result<()> {
    generate_bindings()?;
    setup_wolfssl_link()?;
    scan_cfg()?;
    Ok(())
}

fn wrapper_dir() -> Result<String> {
    Ok(std::env::current_dir()?.display().to_string())
}

fn wolfssl_base_dir() -> Result<String> {
    Ok(format!("{}/../../..", wrapper_dir()?))
}

fn wolfssl_lib_dir() -> Result<String> {
    Ok(format!("{}/src/.libs", wolfssl_base_dir()?))
}

fn bindings_path() -> String {
    PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs").display().to_string()
}

/// Generate Rust bindings for the wolfssl C library using bindgen.
///
/// This function:
/// 1. Sets up the library and include paths
/// 2. Configures the build environment
/// 3. Generates Rust bindings using bindgen
/// 4. Writes the bindings to a file
///
/// Returns `Ok(())` if successful, or an error if binding generation fails.
fn generate_bindings() -> Result<()> {
    let bindings = bindgen::Builder::default()
        .header("headers.h")
        .clang_arg(format!("-I{}", wolfssl_base_dir()?))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .map_err(|_| io::Error::other("Failed to generate bindings"))?;

    bindings
        .write_to_file(bindings_path())
        .map_err(|e| {
            io::Error::other(format!("Couldn't write bindings: {}", e))
        })
}

/// Instruct cargo to link against wolfssl C library
///
/// Returns `Ok(())` if successful, or an error if any step fails.
fn setup_wolfssl_link() -> Result<()> {
    println!("cargo:rustc-link-lib=wolfssl");

//    TODO: do we need this if only a static library is built?
//    println!("cargo:rustc-link-lib=static=wolfssl");

    let build_in_repo = Path::new(&wolfssl_lib_dir()?).exists();
    if build_in_repo {
        // When the crate is built in the wolfssl repository, link with the
        // locally build wolfssl library to allow testing any local changes
        // and running unit tests even if library is not installed.
        println!("cargo:rustc-link-search={}", wolfssl_lib_dir()?);
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", wolfssl_lib_dir()?);
    }

    Ok(())
}

fn read_file(path: String) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

fn check_cfg(binding: &str, function_name: &str, cfg_name: &str) {
    let pattern = format!(r"\b{}\b", function_name);
    let re = match Regex::new(&pattern) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error compiling regex '{}': {}", pattern, e);
            return;
        }
    };
    println!("cargo::rustc-check-cfg=cfg({})", cfg_name);
    if re.is_match(binding) {
        println!("cargo:rustc-cfg={}", cfg_name);
    }
}

fn scan_cfg() -> Result<()> {
    let binding = read_file(bindings_path())?;

    /* aes */
    check_cfg(&binding, "wc_AesSetKey", "aes");
    check_cfg(&binding, "wc_AesCbcEncrypt", "aes_cbc");
    check_cfg(&binding, "wc_AesCcmSetKey", "aes_ccm");
    check_cfg(&binding, "wc_AesCfbEncrypt", "aes_cfb");
    check_cfg(&binding, "wc_AesCtrEncrypt", "aes_ctr");
    check_cfg(&binding, "wc_AesCtsEncrypt", "aes_cts");
    check_cfg(&binding, "wc_AesCfbDecrypt", "aes_decrypt");
    check_cfg(&binding, "wc_AesEaxInit", "aes_eax");
    check_cfg(&binding, "wc_AesEcbEncrypt", "aes_ecb");
    check_cfg(&binding, "wc_AesGcmSetKey", "aes_gcm");
    check_cfg(&binding, "wc_AesGcmInit", "aes_gcm_stream");
    check_cfg(&binding, "wc_AesOfbEncrypt", "aes_ofb");
    check_cfg(&binding, "wc_AesXtsInit", "aes_xts");
    check_cfg(&binding, "wc_AesXtsEncryptInit", "aes_xts_stream");

    /* blake2 */
    check_cfg(&binding, "wc_InitBlake2b", "blake2b");
    check_cfg(&binding, "wc_Blake2bHmac", "blake2b_hmac");
    check_cfg(&binding, "wc_InitBlake2s", "blake2s");
    check_cfg(&binding, "wc_Blake2sHmac", "blake2s_hmac");

    /* chacha20_poly1305 */
    check_cfg(&binding, "wc_ChaCha20Poly1305_Encrypt", "chacha20_poly1305");
    check_cfg(&binding, "wc_XChaCha20Poly1305_Encrypt", "xchacha20_poly1305");

    /* cmac */
    check_cfg(&binding, "wc_InitCmac", "cmac");

    /* curve25519 */
    check_cfg(&binding, "wc_curve25519_make_pub", "curve25519");
    check_cfg(&binding, "wc_curve25519_make_pub_blind", "curve25519_blinding");

    /* dh */
    check_cfg(&binding, "wc_InitDhKey", "dh");
    check_cfg(&binding, "wc_DhGenerateParams", "dh_keygen");
    check_cfg(&binding, "wc_Dh_ffdhe2048_Get", "dh_ffdhe_2048");
    check_cfg(&binding, "wc_Dh_ffdhe3072_Get", "dh_ffdhe_3072");
    check_cfg(&binding, "wc_Dh_ffdhe4096_Get", "dh_ffdhe_4096");
    check_cfg(&binding, "wc_Dh_ffdhe6144_Get", "dh_ffdhe_6144");
    check_cfg(&binding, "wc_Dh_ffdhe8192_Get", "dh_ffdhe_8192");

    /* ecc */
    check_cfg(&binding, "wc_ecc_init", "ecc");
    check_cfg(&binding, "wc_ecc_export_point_der_compressed", "ecc_comp_key");
    check_cfg(&binding, "wc_ecc_shared_secret", "ecc_dh");
    check_cfg(&binding, "wc_ecc_sign_hash", "ecc_sign");
    check_cfg(&binding, "wc_ecc_verify_hash", "ecc_verify");
    check_cfg(&binding, "wc_ecc_export_x963", "ecc_export");
    check_cfg(&binding, "wc_ecc_import_x963", "ecc_import");
    check_cfg(&binding, "ecc_curve_ids_ECC_X25519", "ecc_curve_25519");
    check_cfg(&binding, "ecc_curve_ids_ECC_X448", "ecc_curve_448");
    check_cfg(&binding, "ecc_curve_ids_ECC_SAKKE_1", "ecc_curve_sakke");
    check_cfg(&binding, "ecc_curve_ids_ECC_CURVE_CUSTOM", "ecc_custom_curves");

    /* ed25519 */
    check_cfg(&binding, "wc_ed25519_init", "ed25519");
    check_cfg(&binding, "wc_ed25519_import_public", "ed25519_import");
    check_cfg(&binding, "wc_ed25519_export_public", "ed25519_export");
    check_cfg(&binding, "wc_ed25519_sign_msg", "ed25519_sign");
    check_cfg(&binding, "wc_ed25519_verify_msg_ex", "ed25519_verify");
    check_cfg(&binding, "wc_ed25519_verify_msg_init", "ed25519_streaming_verify");

    /* ed448 */
    check_cfg(&binding, "wc_ed448_init", "ed448");
    check_cfg(&binding, "wc_ed448_import_public", "ed448_import");
    check_cfg(&binding, "wc_ed448_export_public", "ed448_export");
    check_cfg(&binding, "wc_ed448_sign_msg", "ed448_sign");
    check_cfg(&binding, "wc_ed448_verify_msg_ex", "ed448_verify");
    check_cfg(&binding, "wc_ed448_verify_msg_init", "ed448_streaming_verify");

    /* hkdf */
    check_cfg(&binding, "wc_HKDF_Extract_ex", "hkdf");

    /* hmac */
    check_cfg(&binding, "wc_HmacSetKey", "hmac");

    /* kdf */
    check_cfg(&binding, "wc_PBKDF2", "kdf_pbkdf2");
    check_cfg(&binding, "wc_PKCS12_PBKDF_ex", "kdf_pkcs12");
    check_cfg(&binding, "wc_SRTP_KDF", "kdf_srtp");
    check_cfg(&binding, "wc_SSH_KDF", "kdf_ssh");
    check_cfg(&binding, "wc_Tls13_HKDF_Extract_ex", "kdf_tls13");

    /* prf */
    check_cfg(&binding, "wc_PRF", "prf");

    /* random */
    check_cfg(&binding, "wc_RNG_DRBG_Reseed", "random_hashdrbg");
    check_cfg(&binding, "wc_InitRng", "random");

    /* rsa */
    check_cfg(&binding, "wc_InitRsaKey", "rsa");
    check_cfg(&binding, "wc_RsaDirect", "rsa_direct");
    check_cfg(&binding, "wc_MakeRsaKey", "rsa_keygen");
    check_cfg(&binding, "wc_RsaPSS_Sign", "rsa_pss");

    /* sha */
    check_cfg(&binding, "wc_InitSha", "sha");
    check_cfg(&binding, "wc_InitSha224", "sha224");
    check_cfg(&binding, "wc_InitSha256", "sha256");
    check_cfg(&binding, "wc_InitSha384", "sha384");
    check_cfg(&binding, "wc_InitSha512", "sha512");
    check_cfg(&binding, "wc_InitSha3_224", "sha3");
    check_cfg(&binding, "wc_InitShake128", "shake128");
    check_cfg(&binding, "wc_InitShake256", "shake256");

    Ok(())
}
