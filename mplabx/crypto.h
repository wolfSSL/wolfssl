/*
 * File:   crypto.h
 * Author: C15009
 *
 * Created on July 23, 2013, 12:26 PM
 */

#ifndef CRYPTO_H
#define	CRYPTO_H

#ifdef	__cplusplus
extern "C" {
#endif

    typedef struct saCtrl {
        unsigned int CRYPTOALGO : 4;
        unsigned int MULTITASK : 3;
        unsigned int KEYSIZE : 2;
        unsigned int ENCTYPE : 1;
        unsigned int ALGO : 7;
        unsigned int : 3;
        unsigned int FLAGS : 1;
        unsigned int FB : 1;
        unsigned int LOADIV : 1;
        unsigned int LNC : 1;
        unsigned int IRFLAG : 1;
        unsigned int ICVONLY : 1;
        unsigned int OR_EN : 1;
        unsigned int NO_RX : 1;
        unsigned int : 1;
        unsigned int VERIFY : 1;
        unsigned int : 2;
    } saCtrl;

    typedef struct securityAssociation {
        saCtrl SA_CTRL;
        unsigned int SA_AUTHKEY[8];
        unsigned int SA_ENCKEY[8];
        unsigned int SA_AUTHIV[8];
        unsigned int SA_ENCIV[4];
    } securityAssociation;

    typedef struct bdCtrl {
        unsigned int BUFLEN : 16;
        unsigned int CBD_INT_EN : 1;
        unsigned int PKT_INT_EN : 1;
        unsigned int LIFM : 1;
        unsigned int LAST_BD: 1;
        unsigned int : 2;
        unsigned int SA_FETCH_EN : 1;
        unsigned int : 4;
        unsigned int CRY_MODE: 3;
        unsigned int : 1;
        unsigned int DESC_EN : 1;
        /* Naveen did this
        unsigned int CRDMA_EN: 1;
        unsigned int UPD_RES : 1;
        unsigned int SA_FETCH_EN : 1;
        unsigned int SEC_CODE : 1;
        unsigned int : 7;
        unsigned int DESC_EN : 1; */
    } bdCtrl;

    typedef struct bufferDescriptor {
        bdCtrl BD_CTRL;
//        unsigned int BD_CTRL;
        unsigned int SA_ADDR;
        unsigned int SRCADDR;
        unsigned int DSTADDR;
        unsigned int NXTPTR;
        unsigned int UPDPTR;
        unsigned int MSGLEN;
        unsigned int ENCOFF;
    } bufferDescriptor;


#ifdef	__cplusplus
}
#endif

#endif	/* CRYPTO_H */

