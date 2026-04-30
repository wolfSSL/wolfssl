# wolfSSL Espressif CMake Library

This directory contains common functions used in various examples and components.

Instead of duplicating functions in various locations, this common library can be used.

Although it can be used as-is, the intent is to include it in the published wolfSSL Managed Component and include it from there when possible.

## CHECK_DUPLICATE_LIBRARIES

Searches for duplicate directories containing duplicate component libraries.

Parameters:

- RESULT_VAR (output variable)
- KEYWORD (e.g. "wolfssl", "wolfmqtt", etc)
