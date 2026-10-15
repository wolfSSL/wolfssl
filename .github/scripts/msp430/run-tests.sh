#!/bin/sh
set -eu
# flags/main_flags/registers below are lists of literal or validated compiler
# options, intentionally split into separate arguments.
if [ "$#" -eq 0 ]; then set -- small large ecc; fi
trap 'status=$?; if [ "$status" -ne 0 ] && [ -f build.log ]; then tail -n 45 build.log >&2; fi' 0
msp430-elf-gcc --version | head -1
msp430-elf-run --version | head -1

run_case() {
    test_name=$1
    main_flags=$2
    # shellcheck disable=SC2086
    msp430-elf-gcc $flags "-DTEST_NAME=$test_name" $main_flags \
        -c /harness/main.c -o main.o >>build.log 2>&1
    # shellcheck disable=SC2086
    msp430-elf-gcc $flags -Wl,--gc-sections "-Wl,-Map,$test_name.map" \
        ./*.o -o "$test_name.elf" >>build.log 2>&1
    msp430-elf-size "$test_name.elf"
    started=$(date +%s)
    if timeout "${MSP430_TEST_TIMEOUT:-900}" msp430-elf-run "$test_name.elf" \
            >"$test_name.log" 2>&1; then
        cat "$test_name.log"
    else
        status=$?
        cat "$test_name.log"
        echo "$profile/$test_name: simulator failed with status $status" >&2
        return 1
    fi
    # A simulator can stop without the guest finishing; require both signals.
    grep -qx "MSP430_TEST_PASS $test_name" "$test_name.log"
    elapsed=$(( $(date +%s) - started ))
    echo "$profile/$test_name ${elapsed}s" | tee -a /work/timings.txt
}

: >/work/timings.txt
for profile in "$@"; do
    case "$profile" in
        small) model=small; cpu=msp430; extra=; regions=; registers= ;;
        large) model=large; cpu=msp430x; extra=-DMSP430_TEST_LARGE
            regions='-mcode-region=either -mdata-region=either'; registers=-ffixed-r9 ;;
        ecc) model=large; cpu=msp430x
            extra='-DMSP430_TEST_LARGE -DMSP430_TEST_ECC'
            regions='-mcode-region=either -mdata-region=either'; registers=-ffixed-r9 ;;
        *) echo "Unknown profile: $profile" >&2; exit 2 ;;
    esac
    mkdir -p "/work/$profile"
    cd "/work/$profile"
    # Remove this experiment's previous objects so profiles cannot mix.
    rm -f ./*.o
    : >build.log
    multiplier=${MSP430_HWMULT:-none}
    case "$multiplier" in none|f5series) ;; *) echo "Unknown multiplier: $multiplier" >&2; exit 2 ;; esac
    # TI GCC 9.3.1.11 can clobber R9 in a large-model 32-bit shift without
    # preserving it. Reserving R9 avoids corrupting the SP inversion counter.
    flags="-mcpu=$cpu -m$model -msim -mhwmult=$multiplier -Os -g $regions $registers -ffunction-sections -fdata-sections -Werror=implicit-function-declaration -DWOLFSSL_USER_SETTINGS -DNO_MAIN_DRIVER -DWC_TEST_EXPORT_SUBTESTS -DWOLFSSL_TEST_SUBROUTINE= -I/harness -I/src $extra"

    # shellcheck disable=SC2086
    msp430-elf-gcc "-mcpu=$cpu" "-m$model" -msim "-mhwmult=$multiplier" -Os $registers \
        /harness/probe.c -o probe.elf >>build.log 2>&1
    timeout 10 msp430-elf-run probe.elf >probe.log 2>&1
    cat probe.log
    if [ "$model" = small ]; then width=2; else width=4; fi
    grep -qx "MSP430_ABI CHAR_BIT=8 int=2 long=4 pointer=$width size_t=$width" probe.log
    # shellcheck disable=SC2086
    msp430-elf-gcc "-mcpu=$cpu" "-m$model" -msim "-mhwmult=$multiplier" -Os $registers \
        -DMSP430_PROBE_EXIT=7 /harness/probe.c -o fail.elf >>build.log 2>&1
    status=0
    timeout 10 msp430-elf-run fail.elf >fail.log 2>&1 || status=$?
    test "$status" -eq 7
    echo "$profile: deliberate failure correctly returned status 7"

    sources='aes chacha poly1305 chacha20_poly1305 sha256 hash hmac wc_port memory logging error coding wc_encrypt'
    if [ "$profile" = ecc ]; then
        sources="$sources ecc sp_int sp_c32 random wolfmath signature"
    fi
    # shellcheck disable=SC2086
    msp430-elf-gcc $flags -c /src/wolfcrypt/test/test.c -o test.o >>build.log 2>&1
    for source in $sources; do
        # shellcheck disable=SC2086
        msp430-elf-gcc $flags -c "/src/wolfcrypt/src/$source.c" \
            -o "$source.o" >>build.log 2>&1
    done
    if [ "$profile" = ecc ]; then
        # shellcheck disable=SC2086
        msp430-elf-gcc $flags -c /harness/ecdsa_regression.c \
            -o ecdsa_regression.o >>build.log 2>&1
    fi
    case "$profile" in
        small)
            for test_name in sha224_test sha256_test hmac_sha256_test \
                    chacha_test poly1305_test chacha20_poly1305_aead_test \
                    aes_cbc_test aes_ctr_test aesgcm_test; do
                run_case "$test_name" "-DTEST_FUNCTION=$test_name"
            done ;;
        large) run_case symmetric -DMSP430_FULL_SUITE ;;
        ecc) run_case ecc_test -DTEST_FUNCTION=ecc_test ;;
    esac
done
echo 'MSP430_ALL_REQUESTED_PROFILES_PASSED'
