#[cfg(fips)]
fn setup_fips()
{
    use wolfssl_wolfcrypt::fips;
    fips::set_private_key_read_enable(1).expect("Error with set_private_key_read_enable()");
}

pub fn setup()
{
    #[cfg(fips)]
    setup_fips();
}
