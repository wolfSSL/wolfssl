/*
 * @brief AES example
 *
 * @note
 * Copyright(C) NXP Semiconductors, 2015
 * All rights reserved.
 *
 * @par
 * Software that is described herein is for illustrative purposes only
 * which provides customers with programming information regarding the
 * LPC products.  This software is supplied "AS IS" without any warranties of
 * any kind, and NXP Semiconductors and its licensor disclaim any and
 * all warranties, express or implied, including all implied warranties of
 * merchantability, fitness for a particular purpose and non-infringement of
 * intellectual property rights.  NXP Semiconductors assumes no responsibility
 * or liability for the use of the software, conveys no license or rights under any
 * patent, copyright, mask work right, or any other intellectual property rights in
 * or to any products. NXP Semiconductors reserves the right to make changes
 * in the software without notification. NXP Semiconductors also makes no
 * representation or warranty that such application will be suitable for the
 * specified use without further testing or modification.
 *
 * @par
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, under NXP Semiconductors' and its
 * licensor's relevant copyrights in the software, without fee, provided that it
 * is used in conjunction with NXP Semiconductors microcontrollers.  This
 * copyright, permission, and disclaimer notice must appear in all copies of
 * this code.
 */
#include "board.h"
#include <string.h>


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfcrypt/test/test.h>

//#include <wolfcrypt/benchmark/benchmark.h>
extern int benchmark_test(void *args);


/*****************************************************************************
 * Private types/enumerations/variables
 ****************************************************************************/

#define TICKRATE_HZ			1000	/* 1000 ticks per second */

/* UART definitions */
#define LPC_UART			LPC_USART0
#define UARTx_IRQn			USART0_IRQn

/* AES definitions */
#define	CYPHER_CT			16

/* Memory location of the generated random numbers */
uint32_t *RANDOM_NUM = (uint32_t *) 0x40045050;

uint8_t rng_key[CYPHER_CT];
uint32_t rnum[4];

enum { OTP_KEY1=0, OTP_KEY2=1 };
typedef enum { MODE_NONE, MODE_ECB, MODE_CBC } ENCRYPT_T;
typedef enum { KEY_SW, KEY_OTP, KEY_RNG } KEY_T;
typedef struct {
	ENCRYPT_T	encryption;
	ENCRYPT_T	decryption;
	KEY_T		key_src;
	uint32_t	error;
	bool		status;
} CRYPT_CTRL_T;

typedef struct {
	uint32_t	src_chan;					// input:  source DMA channel number (0 - 7)
	uint32_t	dest_chan;					// input:  destination DMA channel number (0 to 7).
	uint32_t	aes_req_in;					// input:  AES input DMA request line (1 or 13)
	uint32_t	aes_req_out;				// input:  AES output DMA request lines (2 or 15)
	uint32_t 	channel_id;					// output: DMA channel ID
	uint32_t	error;						// output: error code returned by ROM calls
	bool		status;						// output: return status for the call
} DMA_CTRL_T;

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/

/*
 * Test encryption (ECB mode) using the following test vectors taken from FIPS-197
 * (key loaded via application)
 *
 * http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-ecb-128
 *
 * PLAINTEXT: 6bc1bee22e409f96e93d7e117393172a (127_0)
 * KEY:       2b7e151628aed2a6abf7158809cf4f3c (127_0)
 * RESULT:    3ad77bb40d7a3660a89ecaf32466ef97 (127_0)
 */
/* Send data to AES in Little Endian Format i.e. LSB in smallest address*/
static uint8_t SWKey[CYPHER_CT] = {
	0x3c, 0x4f, 0xcf, 0x09, 0x88, 0x15, 0xf7, 0xab, 0xa6, 0xd2, 0xae, 0x28, 0x16, 0x15, 0x7e, 0x2b
};

/* Send data to AES engine (Little Endian) */
static uint8_t InitVector[CYPHER_CT] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static uint8_t PlainText[CYPHER_CT] = {
	0x2a, 0x17, 0x93, 0x73, 0x11, 0x7e, 0x3d, 0xe9, 0x96, 0x9f, 0x40, 0x2e, 0xe2, 0xbe, 0xc1, 0x6b
};
static uint8_t Expected_CypherText[CYPHER_CT] = {
	0x97, 0xef, 0x66, 0x24, 0xf3, 0xca, 0x9e, 0xa8, 0x60, 0x36, 0x7a, 0x0d, 0xb4, 0x7b, 0xd7, 0x3a
};

static uint8_t Temp_PlainText[CYPHER_CT];
static uint8_t CypherText[CYPHER_CT];

const char menu1[] = "\r\n"
	"\tt. WolfSSL Test\r\n"
	"\tb. WolfSSL Benchmark\r\n"
	"\t1. AES-128 Encryption using ECB mode without DMA\r\n"
	"\t2. AES-128 Decryption using ECB mode without DMA\r\n"
	"\t3. AES-128 Encryption using CBC mode without DMA\r\n"
	"\t4. AES-128 Decryption using CBC mode without DMA\r\n"
	"\t5. AES-128 Encryption using ECB mode with DMA\r\n"
	"\t6. AES-128 Decryption using ECB mode with DMA\r\n"
	"\t7. AES-128 Encryption using CBC mode with DMA\r\n"
	"\t8. AES-128 Decryption using CBC mode with DMA\r\n";

/*****************************************************************************
 * Private functions
 ****************************************************************************/

/*****************************************************************************
 * Public functions
 ****************************************************************************/

/**
 * @brief	Handle interrupt from SysTick timer
 *			Run the tick every 500ms.
 * @return	Nothing
 */
static uint32_t tick_ct = 0;
void SysTick_Handler(void)
{
	tick_ct++;
	if ((tick_ct % 500) == 0) {
		Board_LED_Toggle(0);
	}
}

/**
 * @brief	Initialize the DMA control structure
 * @return	Nothing
 */
void init_dma_ctrl(DMA_CTRL_T* dma_ctrl)
{
	dma_ctrl->src_chan		= 0;				// input:  source DMA channel number (0 - 7)
	dma_ctrl->dest_chan		= 1;				// input:  destination DMA channel number (0 to 7).
	dma_ctrl->aes_req_in	= 1;				// input:  AES input DMA request line (1 or 13)
	dma_ctrl->aes_req_out	= 2;				// input:  AES output DMA request lines (2 or 15)
	dma_ctrl->channel_id	= 0;				// output: DMA channel ID
	dma_ctrl->error			= LPC_OK;			// output: error code returned by ROM calls
	dma_ctrl->status		= true;				// output: return status for the call
}

/**
 * @brief	Create channel_id
 *
 * The AES DMA functions use channel_id as an input argument.  This function
 * creates and returns channel_id based on the input arguments src_dma_chan_num,
 * dst_dma_chan_num, aes_in_req, and aes_out_req .
 *
 * @param	dma_ctrl: pointer to a DMA_CTRL_T structure
 * @return	nothing
 *
 */
void create_channel_id(DMA_CTRL_T* dma_ctrl)
{
	dma_ctrl->status = true;

	/* Setup source */
	dma_ctrl->channel_id = (dma_ctrl->src_chan << 16) | (dma_ctrl->aes_req_in << 24);
	switch (dma_ctrl->aes_req_in) {
	case 1:
		dma_ctrl->channel_id |= 3 << 28;
		break;

	case 13:
		dma_ctrl->channel_id |= 1 << 28;
		break;

	default:
		dma_ctrl->status = false;
	}

	/* Setup destination */
	dma_ctrl->channel_id |= (dma_ctrl->dest_chan) | (dma_ctrl->aes_req_out << 8);
	switch (dma_ctrl->aes_req_out) {
	case 2:
		dma_ctrl->channel_id |= 3 << 12;
		break;

	case 14:
		dma_ctrl->channel_id |= 1 << 12;
		break;

	default:
		dma_ctrl->status = false;
	}
}

/**
 * @brief	Test results of encrypt
 * @return	Nothing
 */
bool result_test_encrypt(void)
{
	return (memcmp(CypherText, Expected_CypherText, CYPHER_CT) == 0) ? true : false;
}
bool result_test_decrypt(void)
{
	return (memcmp(PlainText, Temp_PlainText, CYPHER_CT) == 0) ? true : false;
}


/**
 * @brief	Extract randomly generated key
 * @return	Nothing
 */
void extract_rngkey(void)
{
	int i=0, j, k;

	for (j = 0; j < 4; j++) {
		rnum[j] = *(RANDOM_NUM+j);
		for (k = 0; k < 4; k++) {
			rng_key[i++] = (0xFF & (rnum[j] >> (k << 3)));
		}
	}
}

/**
 * @brief	Execute encryption without DMA
 * @return	Nothing
 */
void encryption(CRYPT_CTRL_T* ctrl)
{
	ctrl->error = LPC_OK;												/* Initialize error to "no error" */
	ctrl->status = false;												/* Initialize status to fail */
	ctrl->decryption = MODE_NONE;										/* Set decryption mode to none */

	switch (ctrl->key_src) {											/* Load the cypher key */
	case KEY_SW:						
		Chip_AES_LoadKeySW(SWKey);										/* Loads cypher key generated by user-code */
		break;						
	case KEY_OTP:						
		Chip_AES_LoadKey(OTP_KEY1);										/* Loads AES Key1 into AES Engine*/
		break;						
	case KEY_RNG:						
		ctrl->error = Chip_OTP_GenRand();								/* Generate random number */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		Chip_AES_LoadKeyRNG();											/* Load RNG key into the AES engine */
		break;						
	default:						
		DEBUGOUT("Unknown key source\r\n");								/* Report error */
		return;
	}
	
	switch (ctrl->encryption) {											/* Select encryption */
	case MODE_ECB:														/* Electronic Code-book mode */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_ENCODE_ECB);	/* Set the mode to ECB encryption */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_CBC:														/* Cypher block chaining mode */
		Chip_AES_LoadIV_SW(InitVector);									/* Load User defined Initialization Vector */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_ENCODE_CBC);	/* Set the mode to CBC encryption */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_NONE:
		DEBUGOUT("No encryption mode\r\n");								/* Report error */
		return;
	default:						
		DEBUGOUT("Unknown encryption mode\r\n");						/* Report error */
		return;
	}
	ctrl->error = Chip_AES_Operate(CypherText, PlainText, 1);			/* Run the AES Engine */
	if (ctrl->error != LPC_OK) return;									/* Check for errors */
	ctrl->status = true;												/* Set status */
}

/**
 * @brief	Execute decryption without DMA
 * @return	Nothing
 */
void decryption(CRYPT_CTRL_T* ctrl)
{
	ctrl->error = LPC_OK;												/* Initialize error to "no error" */
	ctrl->status = false;												/* Initialize status to fail */

	if (ctrl->encryption != ctrl->decryption) {							/* Is decrypt the same as encrypt? */
		DEBUGOUT("Encrypt and Decrypt do not match\r\n");				/* Report error */
		return;
	}

	switch (ctrl->key_src) {											/* Load the cypher key */
	case KEY_SW:						
		Chip_AES_LoadKeySW(SWKey);										/* Loads cypher key generated by user-code */
		break;						
	case KEY_OTP:						
		Chip_AES_LoadKey(OTP_KEY1);										/* Loads AES Key1 into AES Engine*/
		break;						
	case KEY_RNG:						
		ctrl->error = Chip_OTP_GenRand();								/* Generate random number */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		Chip_AES_LoadKeyRNG();											/* Load RNG key into the AES engine */
		break;						
	default:						
		DEBUGOUT("Unknown key source\r\n");								/* Report error */
		return;
	}
	
	switch (ctrl->decryption) {											/* Select decryption */
	case MODE_ECB:														/* Electronic Code-book mode */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_DECODE_ECB);	/* Set the mode to ECB decryption */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_CBC:														/* Cypher block chaining mode */
		Chip_AES_LoadIV_SW(InitVector);									/* Load User defined Initialization Vector */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_DECODE_CBC);	/* Set the mode to CBC decryption */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_NONE:
		DEBUGOUT("No decryption mode\r\n");								/* Report error */
		return;
	default:						
		DEBUGOUT("Unknown decryption mode\r\n");						/* Report error */
		return;
	}
	ctrl->error = Chip_AES_Operate(Temp_PlainText, CypherText, 1);		/* Run the AES engine */
	if (ctrl->error != LPC_OK) return;									/* Check for errors */
	ctrl->status = true;												/* Set status */
}

/**
 * @brief	Execute encryption with DMA
 * @return	Nothing
 */
void encryption_dma(CRYPT_CTRL_T* ctrl)
{
	DMA_CTRL_T	dma;
	
	ctrl->error = LPC_OK;												/* Initialize error to "no error" */
	ctrl->status = false;												/* Initialize status to fail */
	ctrl->decryption = MODE_NONE;										/* Set decryption mode to none */

	init_dma_ctrl(&dma);												/* Initialize the DMA structure */
	create_channel_id(&dma);											/* create channel_id */
	
	switch (ctrl->key_src) {											/* Load the cypher key */
	case KEY_SW:						
		Chip_AES_LoadKeySW(SWKey);										/* Loads cypher key generated by user-code */
		break;						
	case KEY_OTP:						
		Chip_AES_LoadKey(OTP_KEY1);										/* Loads AES Key1 into AES Engine*/
		break;						
	case KEY_RNG:						
		ctrl->error = Chip_OTP_GenRand();								/* Generate random number */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		Chip_AES_LoadKeyRNG();											/* Load RNG key into the AES engine */
		break;						
	default:						
		DEBUGOUT("Unknown key source\r\n");								/* Report error */
		return;
	}
	
	switch (ctrl->encryption) {											/* Select encryption */
	case MODE_ECB:														/* Electronic Code-book mode */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_ENCODE_ECB);	/* Set the AES mode */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_CBC:														/* Cypher block chaining mode */
		Chip_AES_LoadIV_SW(InitVector);									/* Load User defined Initialization Vector */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_ENCODE_CBC);	/* Set the mode to CBC encryption */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_NONE:
		DEBUGOUT("No encryption mode\r\n");								/* Report error */
		return;
	default:						
		DEBUGOUT("Unknown encryption mode\r\n");						/* Report error */
		return;
	}
	ctrl->error = Chip_AES_Config_DMA(dma.channel_id);					/* Configure DMA channel to process AES block */
	if (ctrl->error != LPC_OK) return;									/* Check for errors */
	ctrl->error = Chip_AES_OperateDMA(dma.channel_id, CypherText, PlainText, 1);	/* Enable DMA, and start AES operation */
	if (ctrl->error != LPC_OK) return;									/* Check for errors */
	while ((Chip_AES_GetStatusDMA(dma.channel_id)) != 0) {}					/* Wait for DMA to complete */
	ctrl->status = true;												/* Set status */
}

/**
 * @brief	Execute decryption with DMA
 * @return	Nothing
 */
void decryption_dma(CRYPT_CTRL_T* ctrl)
{
	DMA_CTRL_T	dma;

	ctrl->error = LPC_OK;												/* Initialize error to "no error" */
	ctrl->status = false;												/* Initialize status to fail */

	init_dma_ctrl(&dma);												/* Initialize the DMA structure */
	create_channel_id(&dma);											/* create channel_id */

	if (ctrl->encryption != ctrl->decryption) {							/* Is decrypt the same as encrypt? */
		DEBUGOUT("Encrypt and Decrypt do not match\r\n");				/* Report error */
		return;
	}

	switch (ctrl->key_src) {											/* Load the cypher key */
	case KEY_SW:						
		Chip_AES_LoadKeySW(SWKey);										/* Loads cypher key generated by user-code */
		break;						
	case KEY_OTP:						
		Chip_AES_LoadKey(OTP_KEY1);										/* Loads AES Key1 into AES Engine*/
		break;						
	case KEY_RNG:						
		ctrl->error = Chip_OTP_GenRand();								/* Generate random number */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		Chip_AES_LoadKeyRNG();											/* Load RNG key into the AES engine */
		break;						
	default:						
		DEBUGOUT("Unknown key source\r\n");								/* Report error */
		return;
	}
	
	switch (ctrl->decryption) {											/* Select decryption */
	case MODE_ECB:														/* Electronic Code-book mode */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_DECODE_ECB);	/* Set the mode to ECB decryption */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_CBC:														/* Cypher block chaining mode */
		Chip_AES_LoadIV_SW(InitVector);									/* Load User defined Initialization Vector */
		ctrl->error = Chip_AES_SetMode(CHIP_AES_API_CMD_DECODE_CBC);	/* Set the mode to CBC decryption */
		if (ctrl->error != LPC_OK) return;								/* Check for errors */
		break;
	case MODE_NONE:
		DEBUGOUT("No decryption mode\r\n");								/* Report error */
		return;
	default:						
		DEBUGOUT("Unknown decryption mode\r\n");						/* Report error */
		return;
	}
	ctrl->error = Chip_AES_Config_DMA(dma.channel_id);					/* Configure DMA channel to process AES block */
	if (ctrl->error != LPC_OK) return;									/* Check for errors */
	ctrl->error = Chip_AES_OperateDMA(dma.channel_id, Temp_PlainText, CypherText, 1);	/* Enable DMA, and start AES operation */
	if (ctrl->error != LPC_OK) return;									/* Check for errors */
	while ((Chip_AES_GetStatusDMA(dma.channel_id)) != 0) {}				/* Wait for DMA to complete */
	ctrl->status = true;												/* Set status */
}

void display_details_encrypt(CRYPT_CTRL_T* ctrl)
{
	int i;
	DEBUGOUT("Summary\r\n");
	DEBUGOUT("------------------------------------------------------\r\n");

	DEBUGOUT("   Plaintext (127-0): ");
	for (i = 15; i >= 0; i--) DEBUGOUT("%02x", PlainText[i]);

	switch (ctrl->key_src) {
	case KEY_SW:
		DEBUGOUT("\r\nSoftware Key (127-0): ");
		for (i = 15; i >= 0; i--) DEBUGOUT("%02x", SWKey[i]);
		break;

	case KEY_RNG:
		extract_rngkey();
		DEBUGOUT("\r\nRNG Key (127-0): ");
		for (i = 15; i >= 0; i--) DEBUGOUT("%02x", rng_key[i]);
		break;
	

	case KEY_OTP:
		DEBUGOUT("\r\nOTP Key (127-0): <cannot be read>");
		break;
	}

	DEBUGOUT("\r\n  CypherText (127-0): ");
	for (i = 15; i >= 0; i--) DEBUGOUT("%02x", CypherText[i]);
	DEBUGOUT("\r\n");
}

void display_details_decrypt(CRYPT_CTRL_T* ctrl)
{
	int i;
	DEBUGOUT("Summary\r\n");
	DEBUGOUT("-----------------------------------------------------\r\n");

	DEBUGOUT("  CypherText (127-0): ");
	for (i = 15; i >= 0; i--) DEBUGOUT("%02x", CypherText[i]);

	switch (ctrl->key_src) {
	case KEY_SW:
		DEBUGOUT("\r\nSoftware Key (127-0): ");
		for (i = 15; i >= 0; i--) DEBUGOUT("%02x", SWKey[i]);
		break;

	case KEY_RNG:
		extract_rngkey();
		DEBUGOUT("\r\nRNG Key (127-0): ");
		for (i = 15; i >= 0; i--) DEBUGOUT("%02x", rng_key[i]);
		break;
	

	case KEY_OTP:
		DEBUGOUT("\r\nOTP Key (127-0): <cannot be read>");
		break;
	}

	DEBUGOUT("\r\n   Plaintext (127-0): ");
	for (i = 15; i >= 0; i--) DEBUGOUT("%02x", Temp_PlainText[i]);
	DEBUGOUT("\r\n");
}

/**
 * @brief	main routine for blinky example
 * @return	Function should not exit.
 */


typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

int main(void)
{
	int opt = 0;
	uint8_t buffer[1];
	CRYPT_CTRL_T enc_ctrl;
	func_args args;
	
	SystemCoreClockUpdate();
	Board_Init();
	Board_UART_Init(LPC_UART);
	Chip_UART_Init(LPC_UART);
	Chip_UART_SetBaud(LPC_UART, 115200);
	Chip_UART_ConfigData(LPC_UART, UART_LCR_WLEN8 | UART_LCR_SBS_1BIT);	/* Default 8-N-1 */
	Chip_UART_TXEnable(LPC_UART);
	Chip_UART_SetupFIFOS(LPC_UART, (UART_FCR_FIFO_EN | UART_FCR_RX_RS |
									UART_FCR_TX_RS | UART_FCR_DMAMODE_SEL | UART_FCR_TRG_LEV0));
	Chip_UART_IntEnable(LPC_UART, (UART_IER_ABEOINT | UART_IER_ABTOINT));
	NVIC_SetPriority(UARTx_IRQn, 1);
	NVIC_EnableIRQ(UARTx_IRQn);

	/* Enable and setup SysTick Timer at a periodic rate */
	SysTick_Config(SystemCoreClock / TICKRATE_HZ);

	Chip_OTP_Init();

	Chip_AES_Init();// Initialize AES block
	DEBUGOUT("AES Engine Initialized...... \r\n");

	while (1) {
		DEBUGOUT("\r\n\t\t\t\tMENU\r\n");
		DEBUGOUT(menu1);
		DEBUGOUT("Please select one of the above options: ");

		opt = 0;
		while (opt == 0) {
			opt = Chip_UART_Read(LPC_UART, buffer, sizeof(buffer));
		}

		switch (buffer[0]) {

		// Encryption using ECB mode without DMA
		case '1':
			enc_ctrl.encryption = MODE_ECB;
			enc_ctrl.key_src = KEY_SW;
			encryption(&enc_ctrl);
			if (enc_ctrl.status == true) {
				DEBUGOUT("\r\nAES Encryption in ECB mode without DMA passed\r\n");
				display_details_encrypt(&enc_ctrl);
			}
			else {
				DEBUGOUT("\r\nAES Encryption in ECB mode without DMA failed\r\n");
			}
			break;
			
		// Decryption using ECB mode without DMA
		case '2':
			enc_ctrl.decryption = MODE_ECB;
			enc_ctrl.key_src = KEY_SW;
			decryption(&enc_ctrl);
			if (enc_ctrl.status == true) {
				DEBUGOUT("\r\nAES Decryption in ECB mode without DMA passed\r\n");
				display_details_decrypt(&enc_ctrl);
			}
			else {
				DEBUGOUT("\r\nAES Decryption in ECB mode without DMA failed\r\n");
			}
			break;


		// Encryption using CBC mode without DMA
		case '3':
			enc_ctrl.encryption = MODE_CBC;
			enc_ctrl.key_src = KEY_SW;
			encryption(&enc_ctrl);
			if (enc_ctrl.status == true) {
				DEBUGOUT("\r\nAES Encryption in CBC mode without DMA passed\r\n");
				display_details_encrypt(&enc_ctrl);
			}
			else {
				DEBUGOUT("\r\nAES Encryption in CBC mode without DMA failed\r\n");
			}
			break;
			
		// Decryption using CBC mode without DMA
		case '4':
			enc_ctrl.decryption = MODE_CBC;
			enc_ctrl.key_src = KEY_SW;
			decryption(&enc_ctrl);
			if (enc_ctrl.status == true) {
				DEBUGOUT("\r\nAES Decryption in CBC mode without DMA passed\r\n");
				display_details_decrypt(&enc_ctrl);
			}
			else {
				DEBUGOUT("\r\nAES Decryption in CBC mode without DMA failed\r\n");
			}
			break;
			
		// Encryption using ECB mode with DMA
		case '5':
			enc_ctrl.encryption = MODE_ECB;
			enc_ctrl.key_src = KEY_SW;
			encryption_dma(&enc_ctrl);
			if (enc_ctrl.status == true) {
				DEBUGOUT("\r\nAES Encryption in ECB mode with DMA passed\r\n");
				display_details_encrypt(&enc_ctrl);
			}
			else {
				DEBUGOUT("\r\nAES Encryption in ECB mode with DMA failed\r\n");
			}
			break;
			
		// Decryption using ECB mode with DMA
		case '6':
			enc_ctrl.decryption = MODE_ECB;
			enc_ctrl.key_src = KEY_SW;
			decryption_dma(&enc_ctrl);
			if (enc_ctrl.status == true) {
				DEBUGOUT("\r\nAES Decryption in ECB mode with DMA passed\r\n");
				display_details_decrypt(&enc_ctrl);
			}
			else {
				DEBUGOUT("\r\nAES Decryption in ECB mode with DMA failed\r\n");
			}
			break;


		// Encryption using CBC mode with DMA
		case '7':
			enc_ctrl.encryption = MODE_CBC;
			enc_ctrl.key_src = KEY_SW;
			encryption_dma(&enc_ctrl);
			if (enc_ctrl.status == true) {
				DEBUGOUT("\r\nAES Encryption in CBC mode with DMA passed\r\n");
				display_details_encrypt(&enc_ctrl);
			}
			else {
				DEBUGOUT("\r\nAES Encryption in CBC mode with DMA failed\r\n");
			}
			break;
			
		// Decryption using CBC mode with DMA
		case '8':
			enc_ctrl.decryption = MODE_CBC;
			enc_ctrl.key_src = KEY_SW;
			decryption_dma(&enc_ctrl);
			if (enc_ctrl.status == true) {
				DEBUGOUT("\r\nAES Decryption in CBC mode with DMA passed\r\n");
				display_details_decrypt(&enc_ctrl);
			}
			else {
				DEBUGOUT("\r\nAES Decryption in CBC mode with DMA passed\r\n");
			}
			break;

		case 't':
			memset(&args, 0, sizeof(args));
			printf("\nCrypt Test\n");
			wolfcrypt_test(&args);
			printf("Crypt Test: Return code %d\n", args.return_code);
			break;

		case 'b':
			memset(&args, 0, sizeof(args));
			printf("\nBenchmark Test\n");
			benchmark_test(&args);
			printf("Benchmark Test: Return code %d\n", args.return_code);
			break;

		// All other cases go here
		default: DEBUGOUT("\r\nSelection out of range\r\n"); break;
		}
	}
}
