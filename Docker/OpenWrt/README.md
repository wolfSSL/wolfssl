This container is really only useful in conjunction with the GitHub Workflow
found in .github/workflows/docker-OpenWrt.yml. The idea is that we will
compile a new libwolfssl that gets placed in official OpenWrt containers to
run some tests ensuring the library is still compatible with existing
binaries.

To run the build locally, you can run (in your wolfSSL root directory):
docker build -t openwrt -f Docker/OpenWrt/Dockerfile .

This should build the entire container and run some sample tests. The resulting
container then can be used to evaluate OpenWrt with the latest wolfSSL library.
