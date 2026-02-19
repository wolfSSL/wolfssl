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
    generate_fips_aliases()?;
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
        .use_core()
        .generate()
        .map_err(|_| io::Error::other("Failed to generate bindings"))?;

    bindings
        .write_to_file(bindings_path())
        .map_err(|e| {
            io::Error::other(format!("Couldn't write bindings: {}", e))
        })
}

/// Generate FIPS symbol aliases.
///
/// Since Rust can't use fips.h's #defines which map the "regular" wc function
/// name to the _fips variant, and since bindgen has only seen the _fips
/// variant, we will generate aliases that allow the non-_fips variant function
/// name to be called without the _fips prefix by Rust sources in a manner
/// similar to which C sources would be able to call the non-_fips variant
/// function name.
///
/// Returns `Ok(())` if successful, or an error if generation fails.
fn generate_fips_aliases() -> Result<()> {
    let binding = read_file(bindings_path())?;
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let aliases_path = out_dir.join("fips_aliases.rs");

    let mut aliases = String::new();

    // Find all _fips symbol names
    let fips_sym_re = Regex::new(r"pub fn (wc_\w+)_fips\s*\(").unwrap();

    for cap in fips_sym_re.captures_iter(&binding) {
        let mut base_name = &cap[1];
        let fips_name = format!("{}_fips", base_name);

        // Exception mappings: (standard_name, fips_name)
        // For cases where FIPS name doesn't follow the simple <name>_fips pattern
        let exceptions: &[(&str, &str)] = &[
            // _ex suffix changed to Ex before _fips
            ("wc_InitRsaKey_ex", "wc_InitRsaKeyEx_fips"),
            ("wc_RsaPublicEncrypt_ex", "wc_RsaPublicEncryptEx_fips"),
            ("wc_RsaPrivateDecryptInline_ex", "wc_RsaPrivateDecryptInlineEx_fips"),
            ("wc_RsaPrivateDecrypt_ex", "wc_RsaPrivateDecryptEx_fips"),
            ("wc_RsaPSS_Sign_ex", "wc_RsaPSS_SignEx_fips"),
            ("wc_RsaPSS_VerifyInline_ex", "wc_RsaPSS_VerifyInlineEx_fips"),
            ("wc_RsaPSS_Verify_ex", "wc_RsaPSS_VerifyEx_fips"),
            ("wc_RsaPSS_CheckPadding_ex", "wc_RsaPSS_CheckPaddingEx_fips"),
            ("wc_DhSetKey_ex", "wc_DhSetKeyEx_fips"),
            ("wc_DhCheckPubKey_ex", "wc_DhCheckPubKeyEx_fips"),
            ("wc_DhCheckPrivKey_ex", "wc_DhCheckPrivKeyEx_fips"),

            // Name change
            ("wc_PRF_TLS", "wc_PRF_TLSv12_fips"),
        ];

        // Handle exceptions
        for (exc_base_name, exc_fips_name) in exceptions {
            if fips_name == *exc_fips_name {
                base_name = exc_base_name;
                break;
            }
        }

        // Check if the non-_fips version exists in bindings
        let non_fips_pattern = format!(r"pub fn {}\s*\(", regex::escape(base_name));
        let non_fips_re = Regex::new(&non_fips_pattern).unwrap();

        if non_fips_re.is_match(&binding) {
            // Add any new known names defined with both a _fips suffix and not
            // here. Warn if any new ones are discovered.
            let known_both = &[
                "wc_AesGcmEncrypt",
                "wc_AesCcmEncrypt",
            ];
            if !known_both.contains(&base_name) {
                println!("cargo:warning=Skipping FIPS symbols alias for {}", base_name);
            }
        } else {
            // Only alias if the base name doesn't already exist
            aliases.push_str(&format!("pub use {} as {};\n", fips_name, base_name));
        }
    }

    fs::write(&aliases_path, aliases)?;

    Ok(())
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

fn check_cfg(binding: &str, function_name: &str, cfg_name: &str) -> bool {
    let pattern = format!(r"\b{}(_fips)?\b", function_name);
    let re = match Regex::new(&pattern) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error compiling regex '{}': {}", pattern, e);
            std::process::exit(1);
        }
    };
    println!("cargo::rustc-check-cfg=cfg({})", cfg_name);
    if re.is_match(binding) {
        println!("cargo:rustc-cfg={}", cfg_name);
        true
    } else {
        false
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
    check_cfg(&binding, "WC_AES_BLOCK_SIZE", "aes_wc_block_size");

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
    if check_cfg(&binding, "ecc_curve_ids_ECC_CURVE_INVALID", "ecc_curve_ids") {
        check_cfg(&binding, "ecc_curve_ids_ECC_SM2P256V1", "ecc_curve_sm2p256v1");
        check_cfg(&binding, "ecc_curve_ids_ECC_X25519", "ecc_curve_25519");
        check_cfg(&binding, "ecc_curve_ids_ECC_X448", "ecc_curve_448");
        check_cfg(&binding, "ecc_curve_ids_ECC_SAKKE_1", "ecc_curve_sakke");
        check_cfg(&binding, "ecc_curve_ids_ECC_CURVE_CUSTOM", "ecc_custom_curves");
    } else {
        check_cfg(&binding, "ecc_curve_id_ECC_SM2P256V1", "ecc_curve_sm2p256v1");
        check_cfg(&binding, "ecc_curve_id_ECC_X25519", "ecc_curve_25519");
        check_cfg(&binding, "ecc_curve_id_ECC_X448", "ecc_curve_448");
        check_cfg(&binding, "ecc_curve_id_ECC_SAKKE_1", "ecc_curve_sakke");
        check_cfg(&binding, "ecc_curve_id_ECC_CURVE_CUSTOM", "ecc_custom_curves");
    }

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

    /* fips */
    check_cfg(&binding, "wc_SetSeed_Cb_fips", "fips");

    /* hkdf */
    check_cfg(&binding, "wc_HKDF_Extract_ex", "hkdf");

    /* hmac */
    check_cfg(&binding, "wc_HmacSetKey", "hmac");
    check_cfg(&binding, "wc_HmacSetKey_ex", "hmac_setkey_ex");

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
    check_cfg(&binding, "wc_RsaSetRNG", "rsa_setrng");
    check_cfg(&binding, "WC_MGF1SHA512_224", "rsa_mgf1sha512_224");
    check_cfg(&binding, "WC_MGF1SHA512_256", "rsa_mgf1sha512_256");
    // Detect whether wc_RsaExportKey takes a const first arg (new API) or non-const (old API)
    let re = Regex::new(r"pub fn wc_RsaExportKey(_fips)?\s*\(\s*\w+\s*:\s*\*\s*const").unwrap();
    println!("cargo::rustc-check-cfg=cfg(rsa_const_api)");
    if re.is_match(&binding) {
        println!("cargo:rustc-cfg=rsa_const_api");
    }

    /* sha */
    check_cfg(&binding, "wc_InitSha", "sha");
    check_cfg(&binding, "wc_InitSha224", "sha224");
    check_cfg(&binding, "wc_InitSha256", "sha256");
    check_cfg(&binding, "wc_InitSha384", "sha384");
    check_cfg(&binding, "wc_InitSha512", "sha512");
    check_cfg(&binding, "wc_HashType_WC_HASH_TYPE_SHA512_224", "sha512_224");
    check_cfg(&binding, "wc_HashType_WC_HASH_TYPE_SHA512_256", "sha512_256");
    check_cfg(&binding, "wc_InitSha3_224", "sha3");
    check_cfg(&binding, "wc_InitShake128", "shake128");
    check_cfg(&binding, "wc_InitShake256", "shake256");

    Ok(())
}
