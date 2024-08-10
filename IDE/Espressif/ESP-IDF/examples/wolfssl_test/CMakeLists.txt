# wolfSSL Espressif Example Project CMakeLists.txt
#   v1.1
#
# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.5)

add_compile_options(-DWOLFSSL_ESP_NO_WATCHDOG=1)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Not only is a project-level "set(COMPONENTS" not needed here, this will cause
# an unintuitive error about  Unknown CMake command "esptool_py_flash_project_args".

project(wolfssl_test)
