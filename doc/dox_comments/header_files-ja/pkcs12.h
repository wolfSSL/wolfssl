/*!
    \ingroup PKCS12
*/
WC_PKCS12* wc_PKCS12_new(void);

/*!
    \ingroup PKCS12
*/
WC_PKCS12* wc_PKCS12_new_ex(void* heap);

/*!
    \ingroup PKCS12
*/
void wc_PKCS12_free(WC_PKCS12* pkcs12);

/*!
    \ingroup PKCS12
*/
int wc_d2i_PKCS12(const byte* der, word32 derSz, WC_PKCS12* pkcs12);

/*!
    \ingroup PKCS12
*/
int wc_d2i_PKCS12_fp(const char* file, WC_PKCS12** pkcs12);

/*!
    \ingroup PKCS12
*/
int wc_i2d_PKCS12(WC_PKCS12* pkcs12, byte** der, int* derSz);

/*!
    \ingroup PKCS12
*/
int wc_PKCS12_parse(WC_PKCS12* pkcs12, const char* psw,
        byte** pkey, word32* pkeySz, byte** cert, word32* certSz,
        WC_DerCertList** ca);

/*!
    \ingroup PKCS12
*/
int wc_PKCS12_parse_ex(WC_PKCS12* pkcs12, const char* psw,
        byte** pkey, word32* pkeySz, byte** cert, word32* certSz,
        WC_DerCertList** ca, int keepKeyHeader);

/*!
    \ingroup PKCS12
*/
WC_PKCS12* wc_PKCS12_create(char* pass, word32 passSz,
        char* name, byte* key, word32 keySz, byte* cert, word32 certSz,
        WC_DerCertList* ca, int nidKey, int nidCert, int iter, int macIter,
        int keyType, void* heap);

/*!
    \ingroup PKCS12
*/
void wc_FreeCertList(WC_DerCertList* list, void* heap);
