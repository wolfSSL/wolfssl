# cmake -P script: run the SBOM driver with SOURCE_DATE_EPOCH set at
# build time.
#
# Keep a value that is already in the environment. When it is empty, use
# the last git commit time of SBOM_ROOT when that directory is the git
# toplevel. A tarball unpacked inside another checkout is not that
# toplevel, so the outer commit time is not used. A tree with no git
# leaves the variable empty, and gen-sbom uses its own default.
#
# When SBOM_STAGE_DIR is set, the build tree SBOM_STAGE_BUILD_DIR is first
# installed with DESTDIR=SBOM_STAGE_DIR, and SBOM_STAGE_LIB must then exist.
# The staging directory is removed after the driver runs, also on failure.
#
# Arguments after "--" are the driver command.

if(NOT DEFINED SBOM_ROOT)
    set(SBOM_ROOT "")
endif()

set(_sde "$ENV{SOURCE_DATE_EPOCH}")
if(_sde STREQUAL "" AND NOT SBOM_ROOT STREQUAL "")
    find_program(_wolfssl_compliance_tooling_git git)
    if(_wolfssl_compliance_tooling_git)
        set(_sde "")
        execute_process(
            COMMAND "${_wolfssl_compliance_tooling_git}" -C "${SBOM_ROOT}"
                    rev-parse --show-toplevel
            OUTPUT_VARIABLE _git_top
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            RESULT_VARIABLE _git_rc)
        if(_git_rc EQUAL 0 AND NOT _git_top STREQUAL "")
            # REALPATH is available on CMake 3.16. file(REAL_PATH) needs 3.19.
            get_filename_component(_root_real "${SBOM_ROOT}" REALPATH)
            get_filename_component(_top_real "${_git_top}" REALPATH)
            if(_root_real STREQUAL _top_real)
                execute_process(
                    COMMAND "${_wolfssl_compliance_tooling_git}" -C "${SBOM_ROOT}"
                            log -1 --format=%ct
                    OUTPUT_VARIABLE _sde
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    ERROR_QUIET
                    RESULT_VARIABLE _git_rc)
                if(NOT _git_rc EQUAL 0)
                    set(_sde "")
                endif()
            endif()
        endif()
        if(NOT _sde STREQUAL "")
            set(ENV{SOURCE_DATE_EPOCH} "${_sde}")
        endif()
    endif()
endif()

math(EXPR _last "${CMAKE_ARGC} - 1")
set(_args "")
set(_seen_dd FALSE)
foreach(_i RANGE 0 ${_last})
    set(_a "${CMAKE_ARGV${_i}}")
    if(_seen_dd)
        # A raw semicolon would split the CMake list and break the argument.
        string(REPLACE ";" "\\;" _safe "${_a}")
        list(APPEND _args "${_safe}")
    elseif(_a STREQUAL "--")
        set(_seen_dd TRUE)
    endif()
endforeach()

if(NOT _args)
    message(FATAL_ERROR "sbom-with-sde.cmake: no command after --")
endif()

if(NOT DEFINED SBOM_STAGE_DIR)
    set(SBOM_STAGE_DIR "")
endif()
if(NOT SBOM_STAGE_DIR STREQUAL "")
    file(REMOVE_RECURSE "${SBOM_STAGE_DIR}")
    # DESTDIR also moves absolute install directories, which --prefix does
    # not. The prefix stays the real one, so the staged file has the same
    # bytes (RPATH, install name) as an installed one. A DESTDIR that the
    # caller set for install-sbom is not used here.
    set(_saved_destdir_set FALSE)
    if(DEFINED ENV{DESTDIR})
        set(_saved_destdir_set TRUE)
        set(_saved_destdir "$ENV{DESTDIR}")
    endif()
    set(ENV{DESTDIR} "${SBOM_STAGE_DIR}")
    set(_install "${CMAKE_COMMAND}" --install "${SBOM_STAGE_BUILD_DIR}")
    if(DEFINED SBOM_STAGE_CONFIG AND NOT SBOM_STAGE_CONFIG STREQUAL "")
        list(APPEND _install --config "${SBOM_STAGE_CONFIG}")
    endif()
    execute_process(COMMAND ${_install} RESULT_VARIABLE _rc)
    if(_saved_destdir_set)
        set(ENV{DESTDIR} "${_saved_destdir}")
    else()
        unset(ENV{DESTDIR})
    endif()
    if(NOT _rc EQUAL 0)
        file(REMOVE_RECURSE "${SBOM_STAGE_DIR}")
        message(FATAL_ERROR
            "SBOM staging install failed (${_rc}). Build the project first.")
    endif()
    if(NOT EXISTS "${SBOM_STAGE_LIB}")
        file(REMOVE_RECURSE "${SBOM_STAGE_DIR}")
        message(FATAL_ERROR
            "SBOM staging: ${SBOM_STAGE_LIB} was not installed. Install the "
            "STAGE_TARGET to CMAKE_INSTALL_LIBDIR, or to CMAKE_INSTALL_BINDIR "
            "for a program or a Windows DLL.")
    endif()
endif()

execute_process(COMMAND ${_args} RESULT_VARIABLE _rc)
if(NOT SBOM_STAGE_DIR STREQUAL "")
    file(REMOVE_RECURSE "${SBOM_STAGE_DIR}")
endif()
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "SBOM generation failed (${_rc})")
endif()
