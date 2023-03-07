/* clu_log.h
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

#ifndef _WOLFSSL_CLU_LOG_H_
#define _WOLFSSL_CLU_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif


/* logging levels */
#define WOLFCLU_L0 0
#define WOLFCLU_L1 1
#define WOLFCLU_L2 2
#define WOLFCLU_E0 -1

typedef void (*wolfCLU_LoggingCb)(int logLevel, const char *const logMsg);
void wolfCLU_OutputON(void);
void wolfCLU_OutputOFF(void);

#ifdef __GNUC__
    #define FMTCHECK_1_2 __attribute__((format(printf,1,2)))
    #define FMTCHECK_2_3 __attribute__((format(printf,2,3)))
#else
    #define FMTCHECK_1_2
    #define FMTCHECK_2_3
#endif /* __GNUC__ */


void wolfCLU_Log(int logLevel, const char *const, ...) FMTCHECK_2_3;
void wolfCLU_LogErrorQueue(void);
void wolfCLU_LogError(const char *const fmt, ...) FMTCHECK_1_2;


#define WOLFCLU_LOG(...) wolfCLU_Log(__VA_ARGS__);


#ifdef __cplusplus
}
#endif

#endif /* _WOLFSSL_CLU_LOG_H_ */

