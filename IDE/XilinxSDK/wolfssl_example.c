/* wolfssl_example.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#include "xil_printf.h"
#include "xrtcpsu.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/logging.h"
#include "wolfcrypt/test/test.h"
#include "wolfcrypt/benchmark/benchmark.h"

/*****************************************************************************
 * Configuration
 ****************************************************************************/

/*****************************************************************************
 * Private types/enumerations/variables
 ****************************************************************************/

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/
typedef struct func_args {
	int argc;
	char** argv;
	int return_code;
} func_args;

const char menu1[] = "\n"
		"\tt. WolfCrypt Test\n"
		"\tb. WolfCrypt Benchmark\n";

/*****************************************************************************
 * Private functions
 ****************************************************************************/
/* Test RNG Seed Function */
/* TODO: Must provide real seed to RNG */
unsigned char my_rng_seed_gen(void)
{
	static unsigned int kTestSeed = 1;
	return kTestSeed++;
}

/*****************************************************************************
 * Public functions
 ****************************************************************************/
int main()
{
	uint8_t cmd;
	func_args args;

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    /* initialize wolfSSL */
    wolfCrypt_Init();

	while (1) {
        memset(&args, 0, sizeof(args));
        args.return_code = NOT_COMPILED_IN; /* default */

		xil_printf("\n\t\t\t\tMENU\n");
		xil_printf(menu1);
		xil_printf("Please select one of the above options:\n");

        do {
        	cmd = inbyte();
        } while (cmd == '\n' || cmd == '\r');

		switch (cmd) {
		case 't':
			xil_printf("Running wolfCrypt Tests...\n");
        #ifndef NO_CRYPT_TEST
			args.return_code = 0;
			wolfcrypt_test(&args);
        #endif
			xil_printf("Crypt Test: Return code %d\n", args.return_code);
			break;

		case 'b':
			xil_printf("Running wolfCrypt Benchmarks...\n");
        #ifndef NO_CRYPT_BENCHMARK
			args.return_code = 0;
			benchmark_test(&args);
        #endif
			xil_printf("Benchmark Test: Return code %d\n", args.return_code);
			break;

		default:
			xil_printf("\nSelection out of range\n");
			break;
		}
	}

    wolfCrypt_Cleanup();

    return 0;
}
