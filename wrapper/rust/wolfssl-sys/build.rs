extern crate bindgen;

use std::env;
use std::io::{self, Result};
use std::path::PathBuf;

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
    // Generate Rust bindings for wolfssl C library.
    generate_bindings()?;
    Ok(())
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
    let wrapper_dir = std::env::current_dir()?.display().to_string();
    let wolfssl_base_dir = format!("{}/../../..", wrapper_dir);
    let wolfssl_lib_dir = format!("{}/src/.libs", wolfssl_base_dir);

    println!("cargo:rustc-link-search={}", wolfssl_lib_dir);
//    TODO: do we need this if only a static library is built?
//    println!("cargo:rustc-link-lib=static=wolfssl");

    let bindings = bindgen::Builder::default()
        .header("headers.h")
        .clang_arg(format!("-I{}", wolfssl_base_dir))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to generate bindings"))?;

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Couldn't write bindings: {}", e),
            )
        })
}
