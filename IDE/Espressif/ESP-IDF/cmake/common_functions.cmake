# IDE/Espressif/ESP-IDF/cmake/common_functions.cmake
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
#


# CHECK_DUPLICATE_LIBRARIES function
#   Parameters:
#      RESULT_VAR (output variable)
#      KEYWORD (e.g. "wolfssl", "wolfmqtt", etc).
#
# Constructs a list of possible directories based on the keyword.
# Counts the number of existing directories.
# If at least two directories exist, sets RESULT_VAR to TRUE, otherwise FALSE.
# Uses PARENT_SCOPE to return the result to the calling context.
function(CHECK_DUPLICATE_LIBRARIES RESULT_VAR KEYWORD)
    set(DIR_LIST
        "${CMAKE_CURRENT_LIST_DIR}/components/${KEYWORD}"
        "${CMAKE_CURRENT_LIST_DIR}/components/my${KEYWORD}"
        "${CMAKE_CURRENT_LIST_DIR}/managed_components/wolfssl__${KEYWORD}"
        "${CMAKE_CURRENT_LIST_DIR}/managed_components/gojimmypi__my${KEYWORD}"
        "${CMAKE_CURRENT_LIST_DIR}/managed_components/${THIS_USER}__my${KEYWORD}"
        "$ENV{IDF_PATH}/components/${KEYWORD}/"
        "$ENV{IDF_PATH}/components/esp-${KEYWORD}/"
    )

    set(EXISTING_COUNT 0)
    set(MATCHING_DIRS "")  # List to store found directories

    foreach(DIR ${DIR_LIST})
        file(TO_CMAKE_PATH "${DIR}" DIR)  # Normalize paths
        message(STATUS "Checking for ${KEYWORD} in ${DIR}")
        if(EXISTS "${DIR}")
            math(EXPR EXISTING_COUNT "${EXISTING_COUNT} + 1")
            list(APPEND MATCHING_DIRS "${DIR}")
            message(STATUS "Found: ${DIR}")
        endif()
    endforeach()

    if(EXISTING_COUNT GREATER_EQUAL 2)
        set(${RESULT_VAR} TRUE PARENT_SCOPE)
        message(STATUS  "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        message(STATUS  "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        message(STATUS  "WARNING: Found duplicate '${KEYWORD}' in")
        foreach(DUP_DIR ${MATCHING_DIRS})
            message(STATUS "  - ${DUP_DIR}")
        endforeach()
        message(STATUS  "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        message(STATUS  "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        message(WARNING "WARNING: More than 1 '${KEYWORD}' component directories exist.")

        # Append the warning flag to CMAKE_C_FLAGS and propagate it to the parent scope
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D${KEYWORD}_MULTI_INSTALL_WARNING")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}" PARENT_SCOPE)
    else()
        set(${RESULT_VAR} FALSE PARENT_SCOPE)

        message(STATUS "Confirmed less than two '${KEYWORD}' component directories exist.")
    endif()
endfunction()
