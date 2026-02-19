#!/bin/bash

set -o noclobber -o nounset -o pipefail -o errexit

mod_path=$1

readarray -t fenceposts < <(readelf --wide --sections --symbols "$mod_path" | awk '
BEGIN {
    fips_fenceposts["wc_linuxkm_pie_reloc_tab"] = "reloc_tab_start";
    fips_fenceposts["wc_linuxkm_pie_reloc_tab_length"] = "reloc_tab_len_start";
    fips_fenceposts["verifyCore"] = "verifyCore_start";
    fips_fenceposts["wolfCrypt_FIPS_first"] = "fips_text_start";
    fips_fenceposts["wolfCrypt_FIPS_last"] = "fips_text_end";
    fips_fenceposts["wolfCrypt_FIPS_ro_start"] = "fips_rodata_start";
    fips_fenceposts["wolfCrypt_FIPS_ro_end"] = "fips_rodata_end";
    singleton_ends["wc_linuxkm_pie_reloc_tab"] = "reloc_tab_end";
    singleton_ends["wc_linuxkm_pie_reloc_tab_length"] = "reloc_tab_len_end";
    singleton_ends["verifyCore"] = "verifyCore_end";
}

/^Section Headers:/ {
    in_sections = 1;
    in_symbols = 0;
    next;
}

/^Symbol table / {
    if (! in_sections) {
        print "symbol table appeared before section headers." >"/dev/stderr";
        exit(1);
    }
    in_sections = 0;
    in_symbols = 1;
    next;
}
{
    if (in_sections) {
        if (match($0,
                  "^[[:space:]]*\\[([^]]+)\\][[:space:]]+\\.([^[:space:].]+)_wolfcrypt[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+([0-9a-f]+)[[:space:]]+([0-9a-f]+)[[:space:]]",
                  section_line_a)) {
            segnum = strtonum(section_line_a[1]);
            segname = section_line_a[2];
            segstart = section_line_a[3];
            segsize = section_line_a[4];
            seg_starts_by_id[segnum] = strtonum("0x" segstart);
            printf("--%s_start\n0x%x\n--%s_end\n0x%x\n", segname, strtonum("0x" segstart), segname, strtonum("0x" segstart) + strtonum("0x" segsize));
            next;
        }
    }
    if (in_symbols) {
        if ($7 !~ "^[0-9]+$")
            next;
        if (($4 != "NOTYPE") && ($4 != "OBJECT") && ($4 != "FUNC"))
            next;
        if (! ($8 in fips_fenceposts))
            next;
        if (! ($7 in seg_starts_by_id)) {
            print "segment offset missing for segment " $7 " for symbol " $8 "." >"/dev/stderr";
            exit(1);
        }
        printf("--%s\n0x%x\n", fips_fenceposts[$8], seg_starts_by_id[$7] + strtonum("0x" $2));
        if ($8 in singleton_ends)
            printf("--%s\n0x%x\n", singleton_ends[$8], seg_starts_by_id[$7] + strtonum("0x" $2) + strtonum($3));
    }
}')

./linuxkm-fips-hash "${fenceposts[@]}" --mod-path "$mod_path" --in-place --quiet
