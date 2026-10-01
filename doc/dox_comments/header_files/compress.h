/*!
    \ingroup Compression

    \brief This function compresses the given input data using Huffman coding
    and stores the output in out. Note that the output buffer should still be
    larger than the input buffer because there exists a certain input for
    which there will be no compression possible, which will still require a
    lookup table. It is recommended that one allocate srcSz + 0.1% + 12 for
    the output buffer.

    \return On successfully compressing the input data, returns the number
    of bytes stored in the output buffer
    \return COMPRESS_INIT_E Returned if there is an error initializing the
    stream for compression
    \return COMPRESS_E Returned if an error occurs during compression

    \param out pointer to the output buffer in which to store the compressed
    data
    \param outSz size available in the output buffer for storage
    \param in pointer to the buffer containing the message to compress
    \param inSz size of the input message to compress
    \param flags flags to control how compression operates. Use 0 for normal
    decompression

    _Example_
    \code
    byte message[] = { // initialize text to compress };
    byte compressed[(sizeof(message) + sizeof(message) * .001 + 12 )];
    // Recommends at least srcSz + .1% + 12

    if( wc_Compress(compressed, sizeof(compressed), message, sizeof(message),
    0) != 0){
    	// error compressing data
    }
    \endcode

    \sa wc_DeCompress
*/
int wc_Compress(byte* out, word32 outSz, const byte* in, word32 inSz, word32 flags);

/*!
    \ingroup Compression

    \brief This function decompresses the given compressed data using Huffman
    coding and stores the output in out.

    \return Success On successfully decompressing the input data, returns the
    number of bytes stored in the output buffer
    \return COMPRESS_INIT_E: Returned if there is an error initializing the
    stream for compression
    \return COMPRESS_E: Returned if an error occurs during compression

    \param out pointer to the output buffer in which to store the decompressed
    data
    \param outSz size available in the output buffer for storage
    \param in pointer to the buffer containing the message to decompress
    \param inSz size of the input message to decompress

    _Example_
    \code
    byte compressed[] = { // initialize compressed message };
    byte decompressed[MAX_MESSAGE_SIZE];

    if( wc_DeCompress(decompressed, sizeof(decompressed),
    compressed, sizeof(compressed)) != 0 ) {
    	// error decompressing data
    }
    \endcode

    \sa wc_Compress
*/
int wc_DeCompress(byte* out, word32 outSz, const byte* in, word32 inSz);

/*!
    \ingroup Compression
    \brief This function compresses the given input data using Huffman
    coding with extended parameters. This is similar to wc_Compress but
    allows specification of compression flags and window bits for more
    control over the compression process.

    \return On successfully compressing the input data, returns the
    number of bytes stored in the output buffer
    \return COMPRESS_INIT_E Returned if there is an error initializing
    the stream for compression
    \return COMPRESS_E Returned if an error occurs during compression

    \param out pointer to the output buffer in which to store the
    compressed data
    \param outSz size available in the output buffer for storage
    \param in pointer to the buffer containing the message to compress
    \param inSz size of the input message to compress
    \param flags flags to control how compression operates
    \param windowBits the base two logarithm of the window size (8..15)

    _Example_
    \code
    byte message[] = { // initialize text to compress };
    byte compressed[(sizeof(message) + sizeof(message) * .001 + 12)];
    word32 flags = 0;
    word32 windowBits = 15; // 32KB window

    int ret = wc_Compress_ex(compressed, sizeof(compressed), message,
                             sizeof(message), flags, windowBits);
    if (ret < 0) {
        // error compressing data
    }
    \endcode

    \sa wc_Compress
    \sa wc_DeCompress_ex
*/
int wc_Compress_ex(byte* out, word32 outSz, const byte* in, word32 inSz,
                   word32 flags, word32 windowBits);

/*!
    \ingroup Compression
    \brief This function decompresses the given compressed data using
    Huffman coding with extended parameters. This is similar to
    wc_DeCompress but allows specification of window bits for more
    control over the decompression process.

    \return On successfully decompressing the input data, returns the
    number of bytes stored in the output buffer
    \return COMPRESS_INIT_E Returned if there is an error initializing
    the stream for decompression
    \return COMPRESS_E Returned if an error occurs during decompression

    \param out pointer to the output buffer in which to store the
    decompressed data
    \param outSz size available in the output buffer for storage
    \param in pointer to the buffer containing the message to decompress
    \param inSz size of the input message to decompress
    \param windowBits the base two logarithm of the window size (8..15)

    _Example_
    \code
    byte compressed[] = { // initialize compressed message };
    byte decompressed[MAX_MESSAGE_SIZE];
    int windowBits = 15;

    int ret = wc_DeCompress_ex(decompressed, sizeof(decompressed),
                               compressed, sizeof(compressed),
                               windowBits);
    if (ret < 0) {
        // error decompressing data
    }
    \endcode

    \sa wc_DeCompress
    \sa wc_Compress_ex
*/
int wc_DeCompress_ex(byte* out, word32 outSz, const byte* in, word32 inSz,
                     int windowBits);

/*!
    \ingroup Compression
    \brief This function decompresses the given compressed data using
    Huffman coding with dynamic memory allocation. The output buffer is
    allocated dynamically and the caller is responsible for freeing it.

    \return On successfully decompressing the input data, returns the
    number of bytes stored in the output buffer
    \return COMPRESS_INIT_E Returned if there is an error initializing
    the stream for decompression
    \return COMPRESS_E Returned if an error occurs during decompression
    \return MEMORY_E Returned if memory allocation fails

    \param out pointer to pointer that will be set to the allocated
    output buffer
    \param max maximum size to allocate for output buffer
    \param memoryType type of memory to allocate (DYNAMIC_TYPE_TMP_BUFFER)
    \param in pointer to the buffer containing the message to decompress
    \param inSz size of the input message to decompress
    \param windowBits the base two logarithm of the window size (8..15)
    \param heap heap hint for memory allocation (can be NULL)

    _Example_
    \code
    byte compressed[] = { // initialize compressed message };
    byte* decompressed = NULL;
    int max = 1024 * 1024; // 1MB max

    int ret = wc_DeCompressDynamic(&decompressed, max,
                                   DYNAMIC_TYPE_TMP_BUFFER, compressed,
                                   sizeof(compressed), 15, NULL);
    if (ret < 0) {
        // error decompressing data
    }
    else {
        // use decompressed data
        XFREE(decompressed, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    \endcode

    \sa wc_DeCompress
    \sa wc_DeCompress_ex
*/
int wc_DeCompressDynamic(byte** out, int max, int memoryType,
                         const byte* in, word32 inSz, int windowBits,
                         void* heap);

/*!
    \ingroup Compression

    \brief Checks whether a compression algorithm is compiled into this build
    and usable with the wc_CompressionData functions. The algorithm ids are
    the TLS CertificateCompressionAlgorithm code points (RFC 8879), e.g.
    WC_ZLIB.

    \return 1 if the algorithm is supported
    \return 0 if the algorithm is not supported, or is WC_NO_COMPRESSION

    \param alg compression algorithm id to check

    _Example_
    \code
    if (wc_IsCompressionAlgSupported(WC_ZLIB)) {
        // zlib can be used
    }
    \endcode

    \sa wc_CompressionData_InitComp
    \sa wc_CompressionData_InitDeComp
*/
byte wc_IsCompressionAlgSupported(word16 alg);

/*!
    \ingroup Compression

    \brief Initializes a wc_CompressionData object to decompress the given
    compressed data. The object does not take ownership of data; it is only
    read from and must stay valid until the object is decompressed or freed.
    If reusing an object, call wc_CompressionData_Free on it first.

    \return 0 on success
    \return BAD_FUNC_ARG if cd or data is NULL, compSz is 0, uncompSz is 0,
    or alg is not
    supported

    \param cd object to initialize
    \param data buffer holding the compressed data
    \param compSz size of the compressed data in bytes
    \param uncompSz exact size of the data once decompressed
    \param alg compression algorithm used to compress data

    _Example_
    \code
    wc_CompressionData cd;
    byte compressed[] = { // compressed data };
    word32 uncompSz = // exact decompressed size;

    if (wc_CompressionData_InitDeComp(&cd, compressed, sizeof(compressed),
            uncompSz, WC_ZLIB) == 0 &&
            wc_CompressionData_DeCompress(&cd) == 0) {
        // cd.data holds cd.uncompressedSz bytes of decompressed data
    }
    wc_CompressionData_Free(&cd);
    \endcode

    \sa wc_CompressionData_DeCompress
    \sa wc_CompressionData_DeCompToBuf
    \sa wc_CompressionData_Free
*/
int wc_CompressionData_InitDeComp(wc_CompressionData* cd,
        const byte* data, word32 compSz, word32 uncompSz,
        word16 alg);

/*!
    \ingroup Compression

    \brief Initializes a wc_CompressionData object to compress the given data.
    The object does not take ownership of data; it is only read from and must
    stay valid until the object is compressed or freed. If reusing an object,
    call wc_CompressionData_Free on it first.

    \return 0 on success
    \return BAD_FUNC_ARG if cd or data is NULL, uncompSz is 0, or alg is not
    supported

    \param cd object to initialize
    \param data buffer holding the data to compress
    \param uncompSz size of data in bytes
    \param alg compression algorithm to use

    _Example_
    \code
    wc_CompressionData cd;
    byte msg[] = { // data to compress };

    if (wc_CompressionData_InitComp(&cd, msg, sizeof(msg), WC_ZLIB) == 0 &&
            wc_CompressionData_Compress(&cd) == 0) {
        // cd.data holds cd.compressedSz bytes of compressed data
    }
    wc_CompressionData_Free(&cd);
    \endcode

    \sa wc_CompressionData_Compress
    \sa wc_CompressionData_CompToBuf
    \sa wc_CompressionData_Free
*/
int wc_CompressionData_InitComp(wc_CompressionData* cd,
        const byte* data, word32 uncompSz, word16 alg);

/*!
    \ingroup Compression

    \brief Sets the heap hint used for buffers that
    wc_CompressionData_Compress and wc_CompressionData_DeCompress allocate.
    Call after the Init function, since Init clears the object.

    \return 0 on success
    \return BAD_FUNC_ARG if cd is NULL

    \param cd initialized object
    \param heap heap hint (can be NULL)

    \sa wc_CompressionData_Compress
    \sa wc_CompressionData_DeCompress
*/
int wc_CompressionData_SetHeap(wc_CompressionData* cd, void* heap);

/*!
    \ingroup Compression

    \brief Releases the buffer owned by the object (the output of a previous
    Compress or DeCompress call), zeroizing it first, and clears the object.
    A buffer passed to an Init function is not freed. Safe to call with NULL.

    \return none No returns.

    \param cd object to free

    \sa wc_CompressionData_InitComp
    \sa wc_CompressionData_InitDeComp
*/
void wc_CompressionData_Free(wc_CompressionData* cd);

/*!
    \ingroup Compression

    \brief Compresses the object's data into a newly allocated buffer, which
    the object then owns. On success cd->data points at the compressed data
    and cd->compressedSz holds its size. Compression fails when the output
    does not fit in the uncompressed size.

    \return 0 on success
    \return BAD_FUNC_ARG if data is NULL, not initialized for compression, or
    the algorithm is not supported
    \return MEMORY_E if allocation fails
    \return COMPRESS_E or another negative value if compression fails

    \param data object initialized with wc_CompressionData_InitComp

    \sa wc_CompressionData_InitComp
    \sa wc_CompressionData_CompToBuf
*/
int wc_CompressionData_Compress(wc_CompressionData* data);

/*!
    \ingroup Compression

    \brief Compresses the object's data into a caller-supplied buffer. The
    object is not modified.

    \return the number of compressed bytes written to out on success
    \return BAD_FUNC_ARG if data or out is NULL or the algorithm is not
    supported
    \return COMPRESS_E or another negative value if compression fails,
    including when out is too small

    \param data object initialized with wc_CompressionData_InitComp
    \param out buffer to write the compressed data to
    \param outSz size of out in bytes

    \sa wc_CompressionData_Compress
*/
int wc_CompressionData_CompToBuf(const wc_CompressionData* data,
        byte* out, word32 outSz);

/*!
    \ingroup Compression

    \brief Decompresses the object's data into a newly allocated buffer of
    cd->uncompressedSz bytes, which the object then owns. On success cd->data
    points at the decompressed data. Decompression fails unless the output is
    exactly the uncompressed size given to wc_CompressionData_InitDeComp.

    \return 0 on success
    \return BAD_FUNC_ARG if data is NULL, not initialized for decompression,
    or the algorithm is not supported
    \return MEMORY_E if allocation fails
    \return BUFFER_E if the decompressed size is too small
    \return other negative values if decompression fails

    \param data object initialized with wc_CompressionData_InitDeComp

    \sa wc_CompressionData_InitDeComp
    \sa wc_CompressionData_DeCompToBuf
*/
int wc_CompressionData_DeCompress(wc_CompressionData* data);

/*!
    \ingroup Compression

    \brief Decompresses the object's data into a caller-supplied buffer. The
    object is not modified.

    \return the number of decompressed bytes written to out on success
    \return BAD_FUNC_ARG if data or out is NULL or the algorithm is not
    supported
    \return BUFFER_E if outSz is smaller than the uncompressed size, or the
    decompressed size does not match it
    \return other negative values if decompression fails

    \param data object initialized with wc_CompressionData_InitDeComp
    \param out buffer to write the decompressed data to
    \param outSz size of out in bytes

    \sa wc_CompressionData_DeCompress
*/
int wc_CompressionData_DeCompToBuf(const wc_CompressionData* data,
        byte* out, word32 outSz);
