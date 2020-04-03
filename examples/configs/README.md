# Example build configurations

These are meant to be copied to your local project and renamed to `user_settings.h`.

## Files

* `user_settings_all.h`: This is wolfSSL with all features enabled. Equivelent to `./configure --enable-all`.
* `user_settings_min_ecc.h`: This is ECC and SHA-256 only. For ECC verify only add `BUILD_VERIFY_ONLY`.
