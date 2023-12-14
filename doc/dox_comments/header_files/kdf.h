
/*!
    \ingroup SrtpKdf

    \brief This function derives keys using SRTP KDF algorithm.

    \return 0 Returned upon successful key derivation.
    \return BAD_FUNC_ARG Returned when key or salt is NULL
    \return BAD_FUNC_ARG Returned when key length is not 16, 24 or 32.
    \return BAD_FUNC_ARG Returned when saltSz is larger than 14.
    \return BAD_FUNC_ARG Returned when kdrIdx is less than -1 or larger than 24.
    \return MEMORY_E on dynamic memory allocation failure.

    \param [in] key Key to use with encryption.
    \param [in] keySz Size of key in bytes.
    \param [in] salt Random non-secret value.
    \param [in] saltSz Size of random in bytes.
    \param [in] kdrIdx Key derivation rate. kdr = 0 when -1, otherwise kdr = 2^kdrIdx.
    \param [in] index Index value to XOR in.
    \param [out] key1 First key. Label value of 0x00.
    \param [in] key1Sz Size of first key in bytes.
    \param [out] key2 Second key. Label value of 0x01.
    \param [in] key2Sz Size of second key in bytes.
    \param [out] key3 Third key. Label value of 0x02.
    \param [in] key3Sz Size of third key in bytes.


    _Example_
    \code
    unsigned char key[16] = { ... };
    unsigned char salt[14] = { ... };
    unsigned char index[6] = { ... };
    unsigned char keyE[16];
    unsigned char keyA[20];
    unsigned char keyS[14];
    int kdrIdx = 0; // Use all of index
    int ret;

    ret = wc_SRTP_KDF(key, sizeof(key), salt, sizeof(salt), kdrIdx, index,
        keyE, sizeof(keyE), keyA, sizeof(keyA), keyS, sizeof(keyS));
    if (ret != 0) {
        WOLFSSL_MSG("wc_SRTP_KDF failed");
    }
    \endcode

    \sa wc_SRTCP_KDF
    \sa wc_SRTP_KDF_label
    \sa wc_SRTCP_KDF_label
    \sa wc_SRTP_KDF_kdr_to_idx
*/
int wc_SRTP_KDF(const byte* key, word32 keySz, const byte* salt, word32 saltSz,
        int kdrIdx, const byte* index, byte* key1, word32 key1Sz, byte* key2,
        word32 key2Sz, byte* key3, word32 key3Sz);

/*!
    \ingroup SrtpKdf

    \brief This function derives keys using SRTCP KDF algorithm.

    \return 0 Returned upon successful key derivation.
    \return BAD_FUNC_ARG Returned when key or salt is NULL
    \return BAD_FUNC_ARG Returned when key length is not 16, 24 or 32.
    \return BAD_FUNC_ARG Returned when saltSz is larger than 14.
    \return BAD_FUNC_ARG Returned when kdrIdx is less than -1 or larger than 24.
    \return MEMORY_E on dynamic memory allocation failure.

    \param [in] key Key to use with encryption.
    \param [in] keySz Size of key in bytes.
    \param [in] salt Random non-secret value.
    \param [in] saltSz Size of random in bytes.
    \param [in] kdrIdx Key derivation rate. kdr = 0 when -1, otherwise kdr = 2^kdrIdx.
    \param [in] index Index value to XOR in.
    \param [out] key1 First key. Label value of 0x00.
    \param [in] key1Sz Size of first key in bytes.
    \param [out] key2 Second key. Label value of 0x01.
    \param [in] key2Sz Size of second key in bytes.
    \param [out] key3 Third key. Label value of 0x02.
    \param [in] key3Sz Size of third key in bytes.


    _Example_
    \code
    unsigned char key[16] = { ... };
    unsigned char salt[14] = { ... };
    unsigned char index[4] = { ... };
    unsigned char keyE[16];
    unsigned char keyA[20];
    unsigned char keyS[14];
    int kdrIdx = 0; // Use all of index
    int ret;

    ret = wc_SRTCP_KDF(key, sizeof(key), salt, sizeof(salt), kdrIdx, index,
        keyE, sizeof(keyE), keyA, sizeof(keyA), keyS, sizeof(keyS));
    if (ret != 0) {
        WOLFSSL_MSG("wc_SRTP_KDF failed");
    }
    \endcode

    \sa wc_SRTP_KDF
    \sa wc_SRTP_KDF_label
    \sa wc_SRTCP_KDF_label
    \sa wc_SRTP_KDF_kdr_to_idx
*/
int wc_SRTCP_KDF(const byte* key, word32 keySz, const byte* salt, word32 saltSz,
        int kdrIdx, const byte* index, byte* key1, word32 key1Sz, byte* key2,
        word32 key2Sz, byte* key3, word32 key3Sz);
/*!
    \ingroup SrtpKdf

    \brief This function derives a key with label using SRTP KDF algorithm.

    \return 0 Returned upon successful key derivation.
    \return BAD_FUNC_ARG Returned when key, salt or outKey is NULL
    \return BAD_FUNC_ARG Returned when key length is not 16, 24 or 32.
    \return BAD_FUNC_ARG Returned when saltSz is larger than 14.
    \return BAD_FUNC_ARG Returned when kdrIdx is less than -1 or larger than 24.
    \return MEMORY_E on dynamic memory allocation failure.

    \param [in] key Key to use with encryption.
    \param [in] keySz Size of key in bytes.
    \param [in] salt Random non-secret value.
    \param [in] saltSz Size of random in bytes.
    \param [in] kdrIdx Key derivation rate. kdr = 0 when -1, otherwise kdr = 2^kdrIdx.
    \param [in] index Index value to XOR in.
    \param [in] label Label to use when deriving key.
    \param [out] outKey Derived key.
    \param [in] outKeySz Size of derived key in bytes.


    _Example_
    \code
    unsigned char key[16] = { ... };
    unsigned char salt[14] = { ... };
    unsigned char index[6] = { ... };
    unsigned char keyE[16];
    int kdrIdx = 0; // Use all of index
    int ret;

    ret = wc_SRTP_KDF_label(key, sizeof(key), salt, sizeof(salt), kdrIdx, index,
        WC_SRTP_LABEL_ENCRYPTION, keyE, sizeof(keyE));
    if (ret != 0) {
        WOLFSSL_MSG("wc_SRTP_KDF failed");
    }
    \endcode

    \sa wc_SRTP_KDF
    \sa wc_SRTCP_KDF
    \sa wc_SRTCP_KDF_label
    \sa wc_SRTP_KDF_kdr_to_idx
*/
int wc_SRTP_KDF_label(const byte* key, word32 keySz, const byte* salt,
        word32 saltSz, int kdrIdx, const byte* index, byte label, byte* outKey,
        word32 outKeySz);
/*!
    \ingroup SrtpKdf

    \brief This function derives key with label using SRTCP KDF algorithm.

    \return 0 Returned upon successful key derivation.
    \return BAD_FUNC_ARG Returned when key, salt or outKey is NULL
    \return BAD_FUNC_ARG Returned when key length is not 16, 24 or 32.
    \return BAD_FUNC_ARG Returned when saltSz is larger than 14.
    \return BAD_FUNC_ARG Returned when kdrIdx is less than -1 or larger than 24.
    \return MEMORY_E on dynamic memory allocation failure.

    \param [in] key Key to use with encryption.
    \param [in] keySz Size of key in bytes.
    \param [in] salt Random non-secret value.
    \param [in] saltSz Size of random in bytes.
    \param [in] kdrIdx Key derivation rate. kdr = 0 when -1, otherwise kdr = 2^kdrIdx.
    \param [in] index Index value to XOR in.
    \param [in] label Label to use when deriving key.
    \param [out] outKey Derived key.
    \param [in] outKeySz Size of derived key in bytes.


    _Example_
    \code
    unsigned char key[16] = { ... };
    unsigned char salt[14] = { ... };
    unsigned char index[4] = { ... };
    unsigned char keyE[16];
    int kdrIdx = 0; // Use all of index
    int ret;

    ret = wc_SRTCP_KDF_label(key, sizeof(key), salt, sizeof(salt), kdrIdx,
        index, WC_SRTCP_LABEL_ENCRYPTION, keyE, sizeof(keyE));
    if (ret != 0) {
        WOLFSSL_MSG("wc_SRTP_KDF failed");
    }
    \endcode

    \sa wc_SRTP_KDF
    \sa wc_SRTCP_KDF
    \sa wc_SRTP_KDF_label
    \sa wc_SRTP_KDF_kdr_to_idx
*/
int wc_SRTP_KDF_label(const byte* key, word32 keySz, const byte* salt,
        word32 saltSz, int kdrIdx, const byte* index, byte label, byte* outKey,
        word32 outKeySz);
/*!
    \ingroup SrtpKdf

    \brief This function converts a kdr value to an index to use in SRTP/SRTCP KDF API.

    \return Key derivation rate as an index.

    \param [in] kdr Key derivation rate to convert.

    _Example_
    \code
    word32 kdr = 0x00000010;
    int kdrIdx;
    int ret;

    kdrIdx = wc_SRTP_KDF_kdr_to_idx(kdr);
    \endcode

    \sa wc_SRTP_KDF
    \sa wc_SRTCP_KDF
    \sa wc_SRTP_KDF_label
    \sa wc_SRTCP_KDF_label
*/
int wc_SRTP_KDF_kdr_to_idx(word32 kdr);

