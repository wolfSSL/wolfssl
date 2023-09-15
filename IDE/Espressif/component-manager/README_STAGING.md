# Espressif Component Staging Notes

Thank you Sergei for these notes:

Recently added: You can add a license field to the manifest:
See [docs](https://docs.espressif.com/projects/idf-component-manager/en/latest/reference/manifest_file.html#manifest-file-idf-component-yml-format-reference)
The description in the docs is not fully correct, it doesn't have to be SPDX string.
The server side is not deployed yet, but it will be there in a couple of days.

Espressif has the test registry at this URL:

https://components-staging.espressif.com/

It's not well reflected in the docs, how to use it, the simplest way is to set “IDF_COMPONENT_REGISTRY_URL=https://components-staging.espressif.com/" environment variable.

Or set it in the [config file](https://docs.espressif.com/projects/idf-component-manager/en/latest/guides/packaging_components.html#authentication-with-a-config-file)

FAQ for the documentation portal WIP, and this topic will be covered there. It should be published this week. (8/14/2023)

Just like on the main server, every version can be uploaded only once. 
You can still delete whatever you want using `compote component delete`, but still,
you cannot re-upload with the same version number. Usually, it's not a limitation because
during development you can use pre-release versions and for fixes of the component with the
same upstream version, "revision" component can be added to the name.

https://docs.espressif.com/projects/idf-component-manager/en/latest/reference/versioning.html#versioning-scheme
