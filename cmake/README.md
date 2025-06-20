# wolfSSL CMake

This directory contains some supplementary functions for the [CMakeLists.txt](../CMakeLists.txt) in the root.

See also cmake notes in the [INSTALL](../INSTALL) documentation file.

If new CMake build options are added `cmake/options.h.in` must also be updated.

For more information on building wolfSSL, see the [wolfSSL Manual](https://www.wolfssl.com/documentation/manuals/wolfssl/).

In summary for cmake:

```
# From the root of the wolfSSL repo:

mkdir -p out
pushd out
cmake ..
cmake --build .

# View the available ciphers with:
./examples/client/client -e
popd
```

## CMake Presets

The `CMakePresets.json`; see [cmake-presets(https://cmake.org/cmake/help/latest/manual/cmake-presets.7.html)

- Cross-platform and cross-IDE.

- Standardized CMake feature (since CMake 3.19+, recommended after 3.21).

- Works in Visual Studio, VS Code, CLI, CI systems, etc..

## Visual Studio Settings

There's also a Visual Studio specific file: `CMakeSettings.json`. This the file that supports the GUI CMake settings.

See the Microsoft [CMakeSettings.json schema reference](https://learn.microsoft.com/en-us/cpp/build/cmakesettings-reference?view=msvc-170)

## Visual Studio (2022 v17.1 and later):

- Prefers `CMakePresets.json` if it exists.

- Falls back to `CMakeSettings.json` if no presets are found.

- Lets you override or extend presets via `CMakeSettings.json`.

### Recommendations:

- Use `CMakePresets.json` to define shared, cross-platform presets.

- Use `CMakeSettings.json` to define Visual Studio-specific overrides, like:
  * Custom output directories
  * Specific environment variables
  * *UI-related tweaks


