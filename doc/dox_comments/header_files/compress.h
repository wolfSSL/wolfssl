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
