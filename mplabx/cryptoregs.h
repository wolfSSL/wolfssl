/* 
 * File:   cryptoregs.h
 * Author: C15009
 *
 * Created on August 14, 2013, 9:44 AM
 */

#ifndef CRYPTOREGS_H
#define	CRYPTOREGS_H

#ifdef	__cplusplus
extern "C" {
#endif

extern volatile unsigned int        CEVER __attribute__((section("sfrs")));
typedef struct {
  unsigned ID:16;
  unsigned VERSION:8;
  unsigned REVISION:8;
} __CEVERbits_t;
extern volatile __CEVERbits_t CEVERbits __asm__ ("CEVER") __attribute__((section("sfrs")));
extern volatile unsigned int        CECON __attribute__((section("sfrs")));
typedef struct {
  unsigned DMAEN:1;
  unsigned BDPPLEN:1;
  unsigned BDPCHST:1;
  unsigned :2;
  unsigned SWAPEN:1;
  unsigned SWRST:1;
} __CECONbits_t;
extern volatile __CECONbits_t CECONbits __asm__ ("CECON") __attribute__((section("sfrs")));
extern volatile unsigned int        CEBDADDR __attribute__((section("sfrs")));
typedef struct {
  unsigned BDPADDR:32;
} __CEBDADDRbits_t;
extern volatile __CEBDADDRbits_t CEBDADDRbits __asm__ ("CEBDADDR") __attribute__((section("sfrs")));
extern volatile unsigned int        CEBDPADDR __attribute__((section("sfrs")));
typedef struct {
  unsigned BASEADDR:32;
} __CEBDPADDRbits_t;
extern volatile __CEBDPADDRbits_t CEBDPADDRbits __asm__ ("CEBDPADDR") __attribute__((section("sfrs")));
extern volatile unsigned int        CESTAT __attribute__((section("sfrs")));
typedef struct {
  unsigned BDCTRL:16;
  unsigned ACTIVE:1;
  unsigned START:1;
  unsigned BDSTATE:4;
  unsigned :2;
  unsigned ERRPHASE:2;
  unsigned ERROP:3;
  unsigned ERRMODE:3;
} __CESTATbits_t;
extern volatile __CESTATbits_t CESTATbits __asm__ ("CESTAT") __attribute__((section("sfrs")));
extern volatile unsigned int        CEINTSRC __attribute__((section("sfrs")));
typedef struct {
  unsigned PENDIF:1;
  unsigned CBDIF:1;
  unsigned PKTIF:1;
  unsigned AREIF:1;
} __CEINTSRCbits_t;
extern volatile __CEINTSRCbits_t CEINTSRCbits __asm__ ("CEINTSRC") __attribute__((section("sfrs")));
extern volatile unsigned int        CEINTEN __attribute__((section("sfrs")));
typedef struct {
  unsigned PENDIE:1;
  unsigned CBDIE:1;
  unsigned PKTIE:1;
  unsigned AREIE:1;
} __CEINTENbits_t;
extern volatile __CEINTENbits_t CEINTENbits __asm__ ("CEINTEN") __attribute__((section("sfrs")));
extern volatile unsigned int        CEPOLLCON __attribute__((section("sfrs")));
typedef struct {
  unsigned BDPPLCON:16;
} __CEPOLLCONbits_t;
extern volatile __CEPOLLCONbits_t CEPOLLCONbits __asm__ ("CEPOLLCON") __attribute__((section("sfrs")));
extern volatile unsigned int        CEHDLEN __attribute__((section("sfrs")));
typedef struct {
  unsigned HDRLEN:8;
} __CEHDLENbits_t;
extern volatile __CEHDLENbits_t CEHDLENbits __asm__ ("CEHDLEN") __attribute__((section("sfrs")));
extern volatile unsigned int        CETRLLEN __attribute__((section("sfrs")));
typedef struct {
  unsigned TRLRLEN:8;
} __CETRLLENbits_t;
extern volatile __CETRLLENbits_t CETRLLENbits __asm__ ("CETRLLEN") __attribute__((section("sfrs")));

#ifdef	__cplusplus
}
#endif

#endif	/* CRYPTOREGS_H */

