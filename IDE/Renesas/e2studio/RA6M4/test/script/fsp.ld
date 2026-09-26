/*
                  Linker File for Renesas FSP
*/

INCLUDE memory_regions.ld
INCLUDE fsp_gen.ld

SECTIONS
{
    .txt.rtt_block (READONLY) :
    {
        KEEP(*(.txt.rtt_block))
    } > RAM
} INSERT AFTER .data
