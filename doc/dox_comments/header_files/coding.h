/*!
    \ingroup Base_Encoding

    \brief This function decodes the given Base64 encoded input, in, and
    stores the result in the output buffer out. It also sets the size
    written to the output buffer in the variable outLen.

    \return 0 Returned upon successfully decoding the Base64 encoded input
    \return BAD_FUNC_ARG Returned if the output buffer is too small to
    store the decoded input
    \return ASN_INPUT_E Returned if a character in the input buffer falls
    outside of the Base64 range ([A-Za-z0-9+/=]) or if there is an invalid
    line ending in the Base64 encoded input

    \param in pointer to the input buffer to decode
    \param inLen length of the input buffer to decode
    \param out pointer to the output buffer in which to store the decoded
    message
    \param outLen pointer to the length of the output buffer. Updated with
    the bytes written at the end of the function call

    _Example_
    \code
    byte encoded[] = { // initialize text to decode };
    byte decoded[sizeof(encoded)];
    // requires at least (sizeof(encoded) * 3 + 3) / 4 room

    int outLen = sizeof(decoded);

    if( Base64_Decode(encoded,sizeof(encoded), decoded, &outLen) != 0 ) {
    	// error decoding input buffer
    }
    \endcode

    \sa Base64_Encode
    \sa Base16_Decode
*/
int Base64_Decode(const byte* in, word32 inLen, byte* out,
                               word32* outLen);

/*!
    \ingroup Base_Encoding

    \brief This function encodes the given input, in, and stores the Base64
    encoded result in the output buffer out. It writes the data with the
    traditional ‘\n’ line endings, instead of escaped %0A line endings. Upon
    successfully completing, this function also sets outLen to the number
    of bytes written to the output buffer.
    If there is enough room in out to store an extra byte, a NULL terminator
    will be added.  This will NOT be included in outLen.

    \return 0 Returned upon successfully decoding the Base64 encoded input
    \return BAD_FUNC_ARG Returned if the output buffer is too small to
    store the encoded input
    \return BUFFER_E Returned if the output buffer runs out of room
    while encoding

    \param in pointer to the input buffer to encode
    \param inLen length of the input buffer to encode
    \param out pointer to the output buffer in which to store the
    encoded message
    \param outLen pointer to the length of the output buffer in
    which to store the encoded message

    _Example_
    \code
    byte plain[] = { // initialize text to encode };
    byte encoded[MAX_BUFFER_SIZE];

    int outLen = sizeof(encoded);

    if( Base64_Encode(plain, sizeof(plain), encoded, &outLen) != 0 ) {
    	// error encoding input buffer
    }
    \endcode

    \sa Base64_EncodeEsc
    \sa Base64_Decode
*/

int Base64_Encode(const byte* in, word32 inLen, byte* out,
                                  word32* outLen);

/*!
    \ingroup Base_Encoding

    \brief This function encodes the given input, in, and stores the
    Base64 encoded result in the output buffer out. It writes the data
    with %0A escaped line endings instead of ‘\n’ line endings.
    Upon successfully completing, this function also sets outLen
    to the number of bytes written to the output buffer.

    \return 0 Returned upon successfully decoding the Base64 encoded input
    \return BAD_FUNC_ARG Returned if the output buffer is too small
    to store the encoded input
    \return BUFFER_E Returned if the output buffer runs out of
    room while encoding
    \return ASN_INPUT_E Returned if there is an error processing
    the decode on the input message

    \param in pointer to the input buffer to encode
    \param inLen length of the input buffer to encode
    \param out pointer to the output buffer in which to store
    the encoded message
    \param outLen pointer to the length of the output buffer in
    which to store the encoded message

    _Example_
    \code
    byte plain[] = { // initialize text to encode };
    byte encoded[MAX_BUFFER_SIZE];

    int outLen = sizeof(encoded);

    if( Base64_EncodeEsc(plain, sizeof(plain), encoded, &outLen) != 0 ) {
    	// error encoding input buffer
    }
    \endcode

    \sa Base64_Encode
    \sa Base64_Decode
*/
int Base64_EncodeEsc(const byte* in, word32 inLen, byte* out,
                                  word32* outLen);

/*!
    \ingroup Base_Encoding

    \brief This function encodes the given input, in, and stores the
    Base64 encoded result in the output buffer out. It writes the data
    with no new lines. Upon successfully completing, this function
    also sets outLen to the number of bytes written to the output buffer

    \return 0 Returned upon successfully decoding the Base64 encoded input
    \return BAD_FUNC_ARG Returned if the output buffer is too small
    to store the encoded input
    \return BUFFER_E Returned if the output buffer runs out of room
    while encoding
    \return ASN_INPUT_E Returned if there is an error processing the
    decode on the input message

    \param in pointer to the input buffer to encode
    \param inLen length of the input buffer to encode
    \param out pointer to the output buffer in which to store the
    encoded message
    \param outLen pointer to the length of the output buffer in which to
    store the encoded message

    _Example_
    \code
    byte plain[] = { // initialize text to encode };
    byte encoded[MAX_BUFFER_SIZE];
    int outLen = sizeof(encoded);
    if( Base64_Encode_NoNl(plain, sizeof(plain), encoded, &outLen) != 0 ) {
    	// error encoding input buffer
    }
    \endcode

    \sa Base64_Encode
    \sa Base64_Decode
*/

int Base64_Encode_NoNl(const byte* in, word32 inLen, byte* out,
                                  word32* outLen);

/*!
    \ingroup Base_Encoding

    \brief This function decodes the given Base16 encoded input, in, and
    stores the result in the output buffer out. It also sets the size written
    to the output buffer in the variable outLen.

    \return 0 Returned upon successfully decoding the Base16 encoded input
    \return BAD_FUNC_ARG Returned if the output buffer is too small to store
    the decoded input or if the input length is not a multiple of two
    \return ASN_INPUT_E Returned if a character in the input buffer falls
    outside of the Base16 range ([0-9A-F])

    \param in pointer to the input buffer to decode
    \param inLen length of the input buffer to decode
    \param out pointer to the output buffer in which to store the decoded
    message
    \param outLen pointer to the length of the output buffer. Updated with the
    bytes written at the end of the function call

    _Example_
    \code
    byte encoded[] = { // initialize text to decode };
    byte decoded[sizeof(encoded)];
    int outLen = sizeof(decoded);

    if( Base16_Decode(encoded,sizeof(encoded), decoded, &outLen) != 0 ) {
    	// error decoding input buffer
    }
    \endcode

    \sa Base64_Encode
    \sa Base64_Decode
    \sa Base16_Encode
*/

int Base16_Decode(const byte* in, word32 inLen, byte* out, word32* outLen);

/*!
    \ingroup Base_Encoding

    \brief Encode input to base16 output.
    If there is enough room in out to store an extra byte, a NULL terminator
    will be added and included in outLen.

    \return 0 Success
    \return BAD_FUNC_ARG Returns if in, out, or outLen is null or if outLen is
    less than 2 times inLen plus 1.

    \param in Pointer to input buffer to be encoded.
    \param inLen Length of input buffer.
    \param out Pointer to output buffer.
    \param outLen Length of output buffer.  Is set to len of encoded output.

    _Example_
    \code
    byte in[] = { // Contents of something to be encoded };
    byte out[NECESSARY_OUTPUT_SIZE];
    word32 outSz = sizeof(out);

    if(Base16_Encode(in, sizeof(in), out, &outSz) != 0)
    {
        // Handle encode error
    }
    \endcode

    \sa Base64_Encode
    \sa Base64_Decode
    \sa Base16_Decode
*/

int Base16_Encode(const byte* in, word32 inLen, byte* out, word32* outLen);

/*!
    \ingroup Base_Encoding
    \brief This function decodes Base64 encoded input without using
    constant-time operations. This is faster than the constant-time
    version but may be vulnerable to timing attacks. Use only when
    timing attacks are not a concern.

    \return 0 On successfully decoding the Base64 encoded input.
    \return BAD_FUNC_ARG If the output buffer is too small to store the
    decoded input.
    \return ASN_INPUT_E If a character in the input buffer falls outside
    of the Base64 range or if there is an invalid line ending.
    \return BUFFER_E If running out of buffer while decoding.

    \param in pointer to the input buffer to decode
    \param inLen length of the input buffer to decode
    \param out pointer to the output buffer to store decoded message
    \param outLen pointer to length of output buffer; updated with bytes
    written

    _Example_
    \code
    byte encoded[] = "SGVsbG8gV29ybGQ="; // "Hello World" in Base64
    byte decoded[64];
    word32 outLen = sizeof(decoded);

    int ret = Base64_Decode_nonCT(encoded, sizeof(encoded)-1, decoded,
                                   &outLen);
    if (ret != 0) {
        // error decoding input
    }
    // decoded now contains "Hello World"
    \endcode

    \sa Base64_Decode
    \sa Base64_Encode
*/
int Base64_Decode_nonCT(const byte* in, word32 inLen, byte* out,
                        word32* outLen);

/*!
    \ingroup Base_Encoding
    \brief This function decodes the UTF-8 encoding of one code point. The
    encodings that RFC 3629 Section 3 requires a decoder to reject are
    rejected: overlong forms, the code points reserved for UTF-16 surrogates,
    code points past the end of the Unicode range, the five and six octet
    forms that RFC 3629 removed, and sequences whose continuation octets are
    missing or malformed. Letting any of those decode to a character would
    allow one octet sequence to impersonate another. The index is only
    advanced when a code point is decoded, so a caller that wants to continue
    past a bad sequence chooses for itself how far to skip.

    \return 0 On successfully decoding one code point.
    \return BAD_FUNC_ARG If in, inOutIdx or cp is NULL.
    \return BUFFER_E If no octets remain, or if the sequence needs more
    continuation octets than the buffer holds.
    \return ASN_INPUT_E If the octets are not a valid encoding of a code
    point.

    \param in pointer to the buffer holding UTF-8 encoded text
    \param inLen length of the input buffer in octets
    \param inOutIdx pointer to the index of the first octet to decode;
    updated to the index of the first octet after the code point decoded
    \param cp pointer to store the decoded code point

    _Example_
    \code
    const byte text[] = { 0xe2, 0x82, 0xac }; // U+20AC
    word32 idx = 0;
    word32 cp;

    while (idx < sizeof(text)) {
        if (wc_Utf8_DecodeChar(text, sizeof(text), &idx, &cp) != 0) {
            // not valid UTF-8 at idx
            break;
        }
        // cp holds the next code point
    }
    \endcode
*/
int wc_Utf8_DecodeChar(const byte* in, word32 inLen, word32* inOutIdx,
                       word32* cp);
