/*------------------------------------------------------------------------------
 * MDK Middleware - Component ::File System:Drive
 * Copyright (c) 2004-2013 ARM Germany GmbH. All rights reserved.
 *------------------------------------------------------------------------------
 * Name:    FS_Config_MC_0.h
 * Purpose: File System Configuration for Memory Card Drive
 * Rev.:    V5.01
 *----------------------------------------------------------------------------*/

//-------- <<< Use Configuration Wizard in Context Menu >>> --------------------

// <h>Memory Card Drive 0
// <i>Configuration for SD/SDHC/MMC Memory Card assigned to drive letter "M0:"
#define MC0_ENABLE              1

//   <o>Connect to hardware via Driver_MCI# <0-255>
//   <i>Select driver control block for hardware interface
#define MC0_MCI_DRIVER          0

//   <o>Connect to hardware via Driver_SPI# <0-255>
//   <i>Select driver control block for hardware interface when in SPI mode
#define MC0_SPI_DRIVER          0

//   <o>Memory Card Interface Mode <0=>Native <1=>SPI
//   <i>Native uses a SD Bus with up to 8 data lines, CLK, and CMD
//   <i>SPI uses 2 data lines (MOSI and MISO), SCLK and CS
//   <i>When using SPI both Driver_SPI# and Driver_MCI# must be specified
//   <i>since the MCI driver provides the control interface lines.
#define MC0_SPI                 0
          
//   <o>Drive Cache Size <0=>OFF <1=>1 KB <2=>2 KB <4=>4 KB
//                       <8=>8 KB <16=>16 KB <32=>32 KB
//   <i>Drive Cache stores data sectors and may be increased to speed-up
//   <i>file read/write operations on this drive (default: 4 KB)
#define MC0_CACHE_SIZE          4

//   <e>Locate Drive Cache and Drive Buffer
//   <i>Some microcontrollers support DMA only in specific memory areas and
//   <i>require to locate the drive buffers at a fixed address.
#define MC0_CACHE_RELOC         0

//     <o>Base address <0x0000-0xFFFFFE00:0x200>
//     <i>Set buffer base address to RAM areas that support DMA with the drive.
#define MC0_CACHE_ADDR          0x7FD00000

//   </e>

//   <q>Use FAT Journal
//   <i>Protect File Allocation Table and Directory Entries for
//   <i>fail-safe operation.
#define MC0_FAT_JOURNAL         0

//   <q>Default Drive "M0:"
//   <i>Use this drive when no drive letter is specified.
#define MC0_DEFAULT_DRIVE       1

// </h>
