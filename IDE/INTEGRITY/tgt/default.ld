// __STAGING_PLATFORM_JACINTO7

// --- Default link map for the INTEGRITY Kernel Address Space ---
//
// Information about the format and various sections of the linker directives
// files can be found in the "Linker Directives Files" section of
// the "Building INTEGRITY Applications" chapter of the INTEGRITY Development
// Guide, and in the "Linker Directives Files" section of the "File Structure"
// chapter of the INTEGRITY BSP User's Guide.
//
// Per-CPU linker directives files included here are located in the common
// library directory corresponding to the BSP. For more infromation refer to
// the "Common Library Directories" section of the INTEGRITY Development
// Guide.

DEFAULTS
{
	__INTEGRITY_DebugBufferSize 	= 0x20000
	__INTEGRITY_DebugEntities   	= 256
	__INTEGRITY_DebugEventLogSize	= 0x400000
	__INTEGRITY_HeapSize 	    	= 0xd0000
	__INTEGRITY_StackSize 	    	= 0x8000
	__INTEGRITY_FiqStackSize    	= 0x2000
	__INTEGRITY_KernelStackSize 	= 0x8000
	__INTEGRITY_DownloadSize    	= 0x300000
	__INTEGRITY_MaxCoreSize     	= 0x0
	__INTEGRITY_BootAreaSize    	= 0x800000
	__INTEGRITY_FlashBufSize    	= 0x40000
}

MEMORY
{
	ram_memory	:	ORIGIN = 0xffffffa000000000, LENGTH = 131072M
	trampoline	:	ORIGIN = 0xffffffffffe00000, LENGTH = 2M
}

SECTIONS
{
	.ramlowerlimit	PAD(0x80000)			: > ram_memory
	.ramstart					: > .
	#include "ram_sections.ld"
	.ramend	 	align(0x1000)			: > ram_memory
	.ramlimit	MEMENDADDR(ram_memory)		:
	.trampoline_begin				: > trampoline
	.trampoline_end	MEMENDADDR(trampoline)		:
}
