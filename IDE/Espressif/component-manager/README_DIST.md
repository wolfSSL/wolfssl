# Espressif Component Manager

This directory does not need to be included in any wolfSSL distributions. The files
contained herein are used only to publish wolfSSL as a managed component to the [ESP Registry](https://components.espressif.com/).

When managing a component:

* Do not edit files in the local `./dist/` directory. Those are file sets previously published.

* Do not edit files in the local `./[project]/managed_components/` directory. Those are files fetched from ESP Registry.

Be sure to edit the [idf_component.yml](./idf_component.yml) version text, _and_ the 
[README_REGISTRY_PREPEND.md](./README_REGISTRY_PREPEND.md) version text. Versions must match between these files.
Values are checked at publish time.

Search for other instances of versions in the format `^1.0.`. Visual Studio File Types: `*.*;!*/dist/*;!*/managed_components/*;!*/.git/*`.
Consider editing older examples.

See the local [wolfssl_component_publish.sh script](./wolfssl_component_publish.sh) for the steps used to copy wolfSSL
source files locally.

The wolfSSL [README.md](https://github.com/wolfSSL/wolfssl/blob/master/README.md) is stripped of an embedded HTML
anchor tags that do not render well.

The local [README_REGISTRY_PREPEND.md](./README_REGISTRY_PREPEND.md) text is prepended to the 
wolfSSL [README.md](https://github.com/wolfSSL/wolfssl/blob/master/README.md) before being published to the registry.

Other README.md files for the examples are appended automatically by the ESP Registry at pubish time.
As such example REAME files must _not_ contain any relative links.

A working Internet connection is required to build the samples.

Any new examples should have a manifest file in the `[project]/main` directory:

```bash
## IDF Component Manager Manifest File
dependencies:
  wolfssl/wolfssl: "^5.6.0-stable"
  ## Required IDF version
  idf:
    version: ">=4.1.0"
  # # Put list of dependencies here
  # # For components maintained by Espressif:
  # component: "~1.0.0"
  # # For 3rd party components:
  # username/component: ">=1.0.0,<2.0.0"
  # username2/component2:
  #   version: "~1.0.0"
  #   # For transient dependencies `public` flag can be set.
  #   # `public` flag doesn't have an effect dependencies of the `main` component.
  #   # All dependencies of `main` are public by default.
  #   public: true
```

  To publish, the ESP-IDF needs to be installed.

```bash
cd /mnt/c/workspace/wolfssl-gojimmypi/IDE/Espressif/component-manager
. /mnt/c/SysGCC/esp32/esp-idf/v5.1/export.sh

```
