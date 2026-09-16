// --- Default link map for INTEGRITY Virtual Address Spaces ---
//
// Section notes are interleaved within the link map.  More information
// can be found in the "Linker Directives Files" section of the "Building
// INTEGRITY Applications" chapter of the INTEGRITY Development Guide.
//

// These default values may be overridden by using -C options on the linker
// command line. Do not change these default values directly.
// Note also that some .bld files in the target directory already override
// these defaults.
DEFAULTS {
    __INTEGRITY_UserLoadBaseAddress   = 64K
    __INTEGRITY_MinPageAlign          = 16K
    __INTEGRITY_MaxPageAlign          = 16K
    __INTEGRITY_ROPageAlign           = 16K
    __INTEGRITY_MaxCacheLineSize      = 128
}

// The start of groups of sections with similar attributes
// like code (read-execute), data (read-only) and data (read-write)
// must be on a page boundary.

SECTIONS {
// begin read-execute code segment - must be page-aligned
    .picbase        __INTEGRITY_UserLoadBaseAddress :
    .text                                           :
    .syscall                                        :
    .intercall                             ALIGN(4) :
    .interfunc                                      :
// .textchecksum MUST be the last section of the read-execute code segment

// Use SHFLAGS to make the text checksum executable so it gets
// merged into the read-execute code segment
    .textchecksum                      SHFLAGS(0x6) :

// begin read-only data segment
    .secinfo         ALIGN(__INTEGRITY_ROPageAlign) :
    .rodata                               ALIGN(16) :
    .sdata2                               ALIGN(16) :
    .fixaddr                                        :
    .fixtype                                        :
// .rodatachecksum MUST be the last section of the read-only data segment
    .rodatachecksum                                 :

// begin data read-write segment - must be page-aligned
    .pidbase        ALIGN(__INTEGRITY_MaxPageAlign) :
// .katomic is a section where variables with atomic operations may be placed
// to ensure the variables are on separate granules with other variables
// allocated for kernel. This assumes (and is Asserted by the kernel)
// that the granule size is less than or equal to the cache line size. .katomic
// allocations shall have the SHT_PROGBITS set (meaning they would have
// otherwise have been placed in the initialized .data section).
    .katomic       ALIGN(__INTEGRITY_MaxCacheLineSize) :
    .katomic_pad   ALIGN(__INTEGRITY_MaxCacheLineSize) :
    .data                                           :
    .sdabase                               ALIGN(8) :
    .sdata                                 ALIGN(8) :
    .toc                                            :
    .opd                                            :
// .datachecksum MUST be the last section of the data portion of the
// data/read/write segment (i.e., it must come before the BSS sections).
    .datachecksum                                   :

// No intitialized data sections should be placed after these bss sections
// unless the first such data section has been aligned to a page boundary.
// Failure to do so will cause all of bss to be pulled into the previous data
// segment, thereby increasing the size of the dynamic download image that
// needs to be transferred to the target.
    .sbss   ALIGN(__INTEGRITY_MinPageAlign)         :
    .bss                                            :
    .earlybss                               NOCLEAR :
    .tksa   ALIGN(__INTEGRITY_MinPageAlign) NOCLEAR :

// Required for C++11 thread local storage, otherwise unused
    .tlsdata                                NOCLEAR :
    .tls.cond.bss                           CLEAR   :
    .tlsbss                                 CLEAR   :
    __ghs_tls_align = max(max(alignof(.tlsdata), alignof(.tlsbss)), alignof(.tls.cond.bss));

// intex will create a heap section unless the following section is uncommented.
// The size of intex heap section defaults to the value of DefaultHeapSize in
// default.bsp.  To override for a particular AddressSpace, define HeapSize in
// the AddressSpace section in the .int file.
//  .heap                    ALIGN(16) PAD(0x10000) :

// Define symbols for members of __ghs_LoaderLoadeeInitialSharedData written by
// intex.
    __ghs_intbegin_heap = __ghs_LoaderLoadeeInitialSharedData +
	16 + 0 * ADDRESS_SIZE;
    __ghs_intend_heap = __ghs_LoaderLoadeeInitialSharedData +
	16 + 1 * ADDRESS_SIZE;
}
