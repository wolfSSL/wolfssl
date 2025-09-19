use std::io::Result;

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
    setup_wolfssl_link()?;
    Ok(())
}

/// Instruct cargo to link against wolfssl C library
///
/// Returns `Ok(())` if successful, or an error if any step fails.
fn setup_wolfssl_link() -> Result<()> {
    let wrapper_dir = std::env::current_dir()?.display().to_string();
    let wolfssl_base_dir = format!("{}/../../..", wrapper_dir);
    let wolfssl_lib_dir = format!("{}/src/.libs", wolfssl_base_dir);

    println!("cargo:rustc-link-search={}", wolfssl_lib_dir);
    println!("cargo:rustc-link-lib=wolfssl");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", wolfssl_lib_dir);

    Ok(())
}
