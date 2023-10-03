# Install for ESP Component Manager

This is the documentation for the wolfSSL install / publish to [components.espressif.com](https://components.espressif.com/components/wolfssl/wolfssl).
When using a managed component, all of the respective source code is in the local project `managed_components` directory.
The wolfssl component `CMakeFiles.txt` from the examples is _not_ used. The managed component is manged entirely by `idf.py`.

See the [Espressif IDF Component Manager Docs](https://docs.espressif.com/projects/idf-component-manager/en/latest/).

Configuration for the component is in the top-level [idf_component.yml](./idf_component.yml) file.
Note that this is *different* from the same-name files in the example projects.

Edit version in:
- Component configuration [idf_component.yml](./idf_component.yml) 
- Example application [lib/idf_component.yml](./lib/idf_component.yml) 
- Example staging application [lib/idf_component.yml](./lib/idf_component-staging-gojimmypi.yml) 
- [README_REGISTRY_PREPEND.md](./README_REGISTRY_PREPEND.md)
Version numbers must exactly match between these files and follow the [Semantic Versioning Specification](https://semver.org/#spec-item-11).

Note that when using the staging environment, the staging user namespace and component name
will be used. There should be a `./lib/idf_component-staging-[user name].yml` file.
For example, for the `gojimmypi` user, the [./lib/idf_component-staging-gojimmypi.yml](./lib/idf_component-staging-gojimmypi.yml)
should contain the alternate namespace (typically the username) and component name (typically with "my" prefix):

```yml
## IDF Component Manager Manifest File
dependencies:
  gojimmypi/mywolfssl: "^5.6.3-f9082c5.2"
```

See the `wolfssl_component_publish.sh` bash script. Set private `IDF_COMPONENT_API_TOKEN`
environment variable as appropriate. Optionally set the `IDF_COMPONENT_REGISTRY_URL`.
Typically there's only one valid option. See [Staging](./INSTALL.md#Staging), below.

```bash
# set your paths as appropriate:
export IDF_COMPONENT_API_TOKEN=YOUR_TOKEN_VALUE
export WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.1
export WOLFSSL_ROOT=/mnt/c/workspace/wolfssl-$USER/IDE/Espressif/component-manager/
export IDF_COMPONENT_REGISTRY_URL=https://components-staging.espressif.com

# install looks for wolfssl-master
cd /mnt/c/workspace/
git clone https://github.com/wolfSSL/wolfssl.git wolfssl-master

cd "$WOLFSSL_ROOT"
echo "Run export.sh from ${WRK_IDF_PATH}"
. ${WRK_IDF_PATH}/export.sh

./wolfssl_component_publish.sh
```

Set the staging environment from PowerShell:
```
$env:IDF_COMPONENT_REGISTRY_URL = "https://components-staging.espressif.com"
```

The script automates the process of populating a directory with wolfSSL source code and examples to publish.
The core command for this is:

```bash
compote component upload --namespace wolfssl --name wolfssl
```

An alternative manual staging looks like this:

```
compote component upload --namespace gojimmypi --name wolfssl
```

The output can be found in the `dist` directory, for example a file called `wolfssl_5.6.0-stable.tgz` and
directory of the contents:

```text
wolfssl_5.6.0-stable
wolfssl_5.6.0-stable.tgz
```

Consider disconnecting local network to go through the whole process without actually
uploading. There's a `dryrun` capability not yet implemented in script.

Examples are copied into the local [./examples/](./examples/README.md) directory.

Each example project needs to have a `main/idf_component.yml` file,
as well as a file called `init_demo.sh`.

The example project `idf_component.yml` file should be edited as needed. Typical contents:

```
## IDF Component Manager Manifest File
dependencies:
  wolfssl/wolfssl: "^5.6.0-stable"
  ## Required IDF version
  idf:
    version: ">=4.1.0"
```

## Staging

There's a staging site at https://components-staging.espressif.com/ for testing deployments.

To use this, set the `IDF_COMPONENT_REGISTRY_URL` environment variable:

```
export IDF_COMPONENT_REGISTRY_URL=https://components-staging.espressif.com/ 
```

This setting is needed for _both_ deployment and client testing of staging-site components.

The default when not set is the production site at https://components.espressif.com

## License File

License field is added to the manifest: See [docs](https://docs.espressif.com/projects/idf-component-manager/en/latest/reference/manifest_file.html#manifest-file-idf-component-yml-format-reference).
The [spdx format license text](https://spdx.org/licenses/) is used.

## ESP Component Examples

Note that when the ESP Component manager installs wolfSSL, then the source code for wolfSSL
will be *in the local component directory*. Normally there's only a cmake file that points
to where the wolfSSL library is located.

Managed components are distinguished by the `idf_component.yml` file in the `projectname/main` directory.

The wolfSSL component must be either managed or non-managed. Not both.

```
idf.py create-project-from-example "gojimmypi/mywolfssl^5.6.3-f9082c5.5:wolfssl_benchmark"
cd wolfssl_benchmark
idf.py -b 115200 flash monitor
```

## Coponent Configuration

Examples such as the wolfssl_server and wolfssl_client need specific parameters set, in particular
the target server IP address, SSID, and SSID password. The `idf.py menuconfig` command is needed.
Set values in `Example Configuration` and `Example Connection Configuration`:

```bash
idf.py menuconfig
```

## Non-ESP Component Example

For a wolfSSL getting started example, see the basic [wolfSSL Template Project](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples/template)
and the [other examples](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples).

Non-managed components are distinguished by having no `idf_component.yml` file in the `projectname/main` directory.
Instead there's a `components/wolfssl/CMakeLists.txt` file.

The wolfSSL component must be either managed or non-managed. Not both.

## Test build of examples

Set `WOLFSSL_ROOT` to the location of the to-be-published wolfSSL directory:

```bash
export WOLFSSL_ROOT=/mnt/c/workspace/wolfssl-gojimmypi-PR/IDE/Espressif/component-manager/
cd "$WOLFSSL_ROOT"
```

The component files in [./lib/components/wolfssl](./lib/components/wolfssl/README.md) will
be copied to each respective example project to confirm they will build.

There's a [wolfssl_build_example.sh](./wolfssl_build_example.sh) script the will temporarily remove
the project `./main/idf_component.yml` component file to ensure the currently-published ESP Registry code
is not used during the build test. That script is called for each of the [component manager examples](./examples/README.md).

The source code for the local examples to be published is copied from [Espressif/ESP-IDF/examples](../ESP-IDF/examples/README.md).


## Common Problems


When there's both `idf_component.yml` file in the `projectname/main` and a
`components/wolfssl/CMakeLists.txt` file, an error such as this will occur:

```
CMake Error at /mnt/c/SysGCC/esp32/esp-idf/v5.1/tools/cmake/component.cmake:250 (message):
  ERROR: Cannot process component requirements.  Multiple candidates to
  satisfy project requirements:

    requirement: "wolfssl" candidates: "wolfssl, wolfssl__wolfssl"
```

To resolve, either:

* Remove the `idf_component.yml` file and remove wolfssl directory from `projectname/managed__components`
* Remove the wolfssl directory from `projectname/components`

### Cannot program, _The chip needs to be in download mode_:

```
Serial port /dev/ttyS9
Connecting......................................

A fatal error occurred: Failed to connect to ESP32: Wrong boot mode detected (0x13)! The chip needs to be in download mode.
For troubleshooting steps visit: https://docs.espressif.com/projects/esptool/en/latest/troubleshooting.html
CMake Error at run_serial_tool.cmake:66 (message):

  /home/gojimmypi/.espressif/python_env/idf5.1_py3.10_env/bin/python;;/mnt/c/SysGCC/esp32/esp-idf/v5.1/components/esptool_py/esptool/esptool.py;--chip;esp32
  failed.



FAILED: CMakeFiles/flash
```

While holding the `boot` button down, tap the `en` button, then release the `boot` button. Try again.

If that didn't work, try the same sequence _after_ you've press `enter` for the `idf.py flash` command
while the `esptool.py` is attempting the upload.

If _that_ didn't work, try the same sequence but press `boot` _before_ you've pressed `enter` 
for the `idf.py flash` command, and press & release `en` _after_ you've pressed `enter` 
while attempting the upload.

If _still_ reading as none of _those_ options worked, try first erasing the flash:

```
idf.py erase-flash -p /dev/ttyS9 -b 115200
```

For a robust programing experience that does not depend on bootloader mode, consider a JTAG
programmer such as the [Tigard](https://github.com/tigard-tools/tigard).

## Cannot find source

```text
Executing action: create-project-from-example
ERROR: Version of the component "gojimmypi/mywolfssl" satisfying the spec "^5.6.3-f9082c5.7" was not found.
```

Check the `IDF_COMPONENT_REGISTRY_URL` setting. Blank defaults to production. See above for staging.

See also [Espressif ESP32 Troubleshooting](https://docs.espressif.com/projects/esptool/en/latest/esp32/troubleshooting.html)
