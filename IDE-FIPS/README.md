# IDE-FIPS

This directory contains FIPS-only IDE builds to better isolate from non-FIPS environments.

When adding a new environment, remember to edit the local [include.am](./include.am) file
and probably create a new `IDE-FIPS/<NEW-OE>/include.am` file as well.
