/* ORIGIN()/LENGTH() always see the SoC memory regions: */
INCLUDE memory.ld

/* Region boundary symbols derived from memory.ld */
PROVIDE(__dram0_start = ORIGIN(dram0_0_seg));
PROVIDE(__dram0_end   = ORIGIN(dram0_0_seg) + LENGTH(dram0_0_seg));

PROVIDE(__drom0_start = ORIGIN(drom0_0_seg));
PROVIDE(__drom0_end   = ORIGIN(drom0_0_seg) + LENGTH(drom0_0_seg));
