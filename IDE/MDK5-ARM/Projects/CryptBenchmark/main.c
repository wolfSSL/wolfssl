/* main.c
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include "wolfcrypt/test/test.h"

#warning "write MPU specific Set ups\n"
    
static void SystemClock_Config (void) {

}

static void MPU_Config (void) {

}

static void CPU_CACHE_Enable (void) {

}

/*-----------------------------------------------------------------------------
 *        Initialize a Flash Memory Card
 *----------------------------------------------------------------------------*/
#if !defined(NO_FILESYSTEM)
#include "rl_fs.h"                      /* FileSystem definitions             */

static void init_filesystem (void) {
  int32_t retv;

  retv = finit ("M0:");
  if (retv == fsOK) {
    retv = fmount ("M0:");
    if (retv == fsOK) {
      printf ("Drive M0 ready!\n");
    }
    else {
      printf ("Drive M0 mount failed(%d)!\n", retv);
    }
  }
  else {
    printf ("Drive M0 initialization failed!\n");
  }
}
#endif

/*-----------------------------------------------------------------------------
 *       mian entry
 *----------------------------------------------------------------------------*/
void benchmark_test(void *arg) ;

int main()
{
    void * arg = NULL ;
    
    MPU_Config(); 
    CPU_CACHE_Enable();
    HAL_Init();                        /* Initialize the HAL Library     */
    SystemClock_Config();              /* Configure the System Clock     */
    BSP_IO_Init();                     /* Enable BSP module              */
    BSP_IO_ConfigPin(IO_PIN_11, IO_MODE_OUTPUT_OD_PU);
    BSP_IO_WritePin (IO_PIN_11, BSP_IO_PIN_RESET); /* Put camera in reset state */

  	#if !defined(NO_FILESYSTEM)
    init_filesystem ();
	  #endif

    printf("=== Start: Crypt Benchmark ===\n") ;
    benchmark_test(arg) ;
    printf("=== End: Crypt Benchmark  ===\n") ;

}

