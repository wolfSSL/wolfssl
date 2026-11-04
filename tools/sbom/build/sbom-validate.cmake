# cmake -P script: validate the SPDX file and write the tag-value file.
# pyspdxtools fails on an invalid document, so this is the same check as
# the pyspdxtools step of `make sbom`.
#
# The paths use the rules of sbom-paths.cmake, so install-sbom installs the
# file that this script writes.

if(NOT DEFINED WOLFSSL_COMPLIANCE_TOOLING_PYSPDXTOOLS OR
   WOLFSSL_COMPLIANCE_TOOLING_PYSPDXTOOLS STREQUAL "")
    message(FATAL_ERROR "sbom-validate.cmake: WOLFSSL_COMPLIANCE_TOOLING_PYSPDXTOOLS is required")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/sbom-paths.cmake")
set(WOLFSSL_COMPLIANCE_TOOLING_SBOM_TV_FROM_SPDX ON)
wolfssl_compliance_tooling_sbom_resolve_outputs(_cdx _spdx _tv)

if(NOT EXISTS "${_spdx}")
    message(FATAL_ERROR "sbom-validate.cmake: missing SPDX file ${_spdx}")
endif()

execute_process(
    COMMAND "${WOLFSSL_COMPLIANCE_TOOLING_PYSPDXTOOLS}"
            --infile "${_spdx}" --outfile "${_tv}"
    RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
    file(REMOVE "${_tv}")
    message(FATAL_ERROR "SPDX validation failed (${_rc}) for ${_spdx}")
endif()
