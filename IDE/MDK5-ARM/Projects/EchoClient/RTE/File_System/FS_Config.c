/*------------------------------------------------------------------------------
 * MDK Middleware - Component ::File System
 * Copyright (c) 2004-2013 ARM Germany GmbH. All rights reserved.
 *------------------------------------------------------------------------------
 * Name:    FS_Config.c
 * Purpose: File System Configuration
 * Rev.:    V5.00
 *----------------------------------------------------------------------------*/

//-------- <<< Use Configuration Wizard in Context Menu >>> --------------------

// <h>File System
// <i>Define File System global parameters

//   <o>Number of open files <4-16>
//   <i>Define number of files that can be
//   <i>opened at the same time.
//   <i>Default: 8
#define NUM_FILES               8

//   <o>FAT Name Cache Size <0-1000000>
//   <i>Define number of cached FAT file or directory names.
//   <i>48 bytes of RAM is required for each cached name.
#define FAT_NAME_CACHE_SIZE     0

//   <e>Relocate FAT Name Cache Buffer
//   <i>Locate Cache Buffer at a specific address.
#define FAT_NAME_CACHE_RELOC    0

//     <o>Base address <0x0000-0xFFFFFE00:0x200>
//     <i>Define the Cache buffer base address.
#define FAT_NAME_CACHE_ADDR     0x60000000

//   </e>

// </h>

#include "..\RTE_Components.h"

#ifdef  RTE_FileSystem_Drive_RAM
#include "FS_Config_RAM.h"
#endif

#ifdef  RTE_FileSystem_Drive_NOR_0
#include "FS_Config_NOR_0.h"
#endif
#ifdef  RTE_FileSystem_Drive_NOR_1
#include "FS_Config_NOR_1.h"
#endif

#ifdef  RTE_FileSystem_Drive_NAND_0
#include "FS_Config_NAND_0.h"
#endif
#ifdef  RTE_FileSystem_Drive_NAND_1
#include "FS_Config_NAND_1.h"
#endif

#ifdef  RTE_FileSystem_Drive_MC_0
#include "FS_Config_MC_0.h"
#endif
#ifdef  RTE_FileSystem_Drive_MC_1
#include "FS_Config_MC_1.h"
#endif

#ifdef  RTE_FileSystem_Drive_USB_0
#include "FS_Config_USB_0.h"
#endif
#ifdef  RTE_FileSystem_Drive_USB_1
#include "FS_Config_USB_1.h"
#endif

#include "fs_config.h"
