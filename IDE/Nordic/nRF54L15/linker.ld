/* nRF54L15 application core: RRAM at 0, both RAM banks as one region.
 * Section layout comes from the Nordic MDK's nrf_common.ld (found through
 * -L <nrfx>/mdk). */

SEARCH_DIR(.)
GROUP(-lgcc -lc)

MEMORY
{
  FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 0x17D000
  RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 0x40000
}

INCLUDE "nrf_common.ld"
