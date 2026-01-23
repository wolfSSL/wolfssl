-- wolfssl.ads
--
-- Copyright (C) 2006-2025 wolfSSL Inc.
--
-- This file is part of wolfSSL.
--
-- wolfSSL is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- wolfSSL is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
--

with Interfaces.C;

--  This package is annotated "with SPARK_Mode" that SPARK can verify
--  the API of this package is used correctly.
package WolfSSL with SPARK_Mode is

   type Subprogram_Result is new Integer;
   Success : constant Subprogram_Result;
   --  Indicates success for some functions.
   --  Do not use, unless you know what you do.

   Failure : constant Subprogram_Result;
   --  Indicates failure for some functions.
   --  Do not use, unless you know what you do.

   Exception_Error : constant := -1234567;
   --  Indicates an exception was raised during a subprogram call.

   function Initialize return Subprogram_Result;
   --  Initializes the wolfSSL library for use. Must be called once per
   --  application and before any other call to the library.

   function Finalize return Subprogram_Result;
   --  Un-initializes the wolfSSL library from further use.
   --  Doesn't have to be called, though it will free any resources
   --  used by the library.

   subtype unsigned is Interfaces.C.unsigned;

   subtype Byte_Type  is Interfaces.C.char;
   subtype Byte_Index is Interfaces.C.size_t range 0 .. 16_000;
   subtype Byte_Array is Interfaces.C.char_array;

   use type Interfaces.C.size_t;

   type Context_Type is limited private with
     Annotate => (GNATprove, Ownership, "Needs_Reclamation");
   --  Instances of this type are called SSL Contexts.

   function Is_Valid (Context : Context_Type) return Boolean with
      Annotate => (GNATprove, Ownership, "Needs_Reclamation");
   --  Indicates if the SSL Context has successfully been initialized.
   --  If initialized, the SSL Context has allocated resources
   --  that needs to be deallocated before application exit.
   --  Annotation added for GNATprove ownership analysis.
   --    https://docs.adacore.com/spark2014-docs/html/ug/en/appendix/additional_annotate_pragmas.html#annotation-for-enforcing-ownership-checking-on-a-private-type

   type Method_Type is limited private with
     Annotate => (GNATprove, Ownership, "Needs_Reclamation");

   function Is_Valid (Method : Method_Type) return Boolean with
      Annotate => (GNATprove, Ownership, "Needs_Reclamation");
   --  Annotation added for GNATprove ownership analysis.
   --    https://docs.adacore.com/spark2014-docs/html/ug/en/appendix/additional_annotate_pragmas.html#annotation-for-enforcing-ownership-checking-on-a-private-type

   function TLSv1_2_Server_Method return Method_Type;
   --  This function is used to indicate that the application is a server
   --  and will only support the TLS 1.2 protocol.

   function TLSv1_2_Client_Method return Method_Type;
   --  This function is used to indicate that the application is a client
   --  and will only support the TLS 1.2 protocol.

   function TLSv1_3_Server_Method return Method_Type;
   --  This function is used to indicate that the application is a server
   --  and will only support the TLS 1.3 protocol.

   function TLSv1_3_Client_Method return Method_Type;
   --  This function is used to indicate that the application is a client
   --  and will only support the TLS 1.3 protocol.

   function DTLSv1_2_Server_Method return Method_Type;
   --  This function is used to indicate that the application is a server
   --  and will only support the DTLS 1.2 protocol.

   function DTLSv1_2_Client_Method return Method_Type;
   --  This function is used to indicate that the application is a client
   --  and will only support the DTLS 1.2 protocol.

   function DTLSv1_3_Server_Method return Method_Type;
   --  This function is used to indicate that the application is a server
   --  and will only support the DTLS 1.3 protocol.

   function DTLSv1_3_Client_Method return Method_Type;
   --  This function is used to indicate that the application is a client
   --  and will only support the DTLS 1.3 protocol.

   procedure Create_Context (Method  : in out Method_Type;
                             Context : out Context_Type) with
      Post => not Is_Valid (Method);
   --  This function creates a new SSL context, taking a desired SSL/TLS
   --  protocol method for input.
   --  If successful Is_Valid (Context) = True, otherwise False.
   --  The Method is consumed by this operation and set to null.

   procedure Free (Context : in out Context_Type) with
      Post => not Is_Valid (Context);
   --  This function frees an allocated SSL Context object.
   --  If Context is not valid, this is a no-op.

   type Mode_Type is private;

   function "or" (Left, Right : Mode_Type) return Mode_Type;

   Verify_None : constant Mode_Type;
   --  Client mode: the client will not verify the certificate received
   --  from the server and the handshake will continue as normal.
   --
   --  Server mode: the server will not send a certificate request to
   --  the client. As such, client verification will not be enabled.

   Verify_Peer : constant Mode_Type;
   --  Client mode: the client will verify the certificate received from
   --  the server during the handshake. This is turned on by default
   --  in wolfSSL, therefore, using this option has no effect.
   --
   --  Server mode: the server will send a certificate request to
   --  the client and verify the client certificate received.

   Verify_Fail_If_No_Peer_Cert : constant Mode_Type;
   --  Client mode: no effect when used on the client side.
   --
   --  Server mode: the verification will fail on the server side if
   --  the client fails to send a certificate when requested to do so
   --  (when using Verify_Peer on the SSL server).

   Verify_Client_Once : constant Mode_Type;

   Verify_Post_Handshake : constant Mode_Type;

   Verify_Fail_Except_Psk : constant Mode_Type;
   --  Client mode: no effect when used on the client side.
   --
   --  Server mode: the verification is the same as
   --  Verify_Fail_If_No_Peer_Cert except in the case of a PSK connection.
   --  If a PSK connection is being made then the connection
   --  will go through without a peer cert.

   Verify_Default : constant Mode_Type;

   procedure Set_Verify (Context : Context_Type;
                         Mode    : Mode_Type) with
      Pre => Is_Valid (Context);
   --  This function sets the verification method for remote peers

   function Get_Verify (Context : Context_Type) return Mode_Type;

   type File_Format is private;

   Format_Asn1    : constant File_Format;
   Format_Pem     : constant File_Format;
   Format_Default : constant File_Format;

   function Use_Certificate_File (Context : Context_Type;
                                  File    : String;
                                  Format  : File_Format)
                                  return Subprogram_Result with
      Pre => Is_Valid (Context);
   --  This function loads a certificate file into the SSL context.
   --  The file is provided by the file argument. The format argument
   --  specifies the format type of the file, either ASN1 or
   --  PEM file types. Please see the examples for proper usage.

   function Use_Certificate_Buffer (Context : Context_Type;
                                    Input   : Byte_Array;
                                    Format  : File_Format)
                                    return Subprogram_Result with
      Pre => Is_Valid (Context);
   --  This function loads a certificate buffer into the SSL Context.
   --  It behaves like the non-buffered version (Use_Certificate_File),
   --  only differing in its ability to be called with a buffer as input
   --  instead of a file. The buffer is provided by the Input argument.
   --  Format specifies the format type of the buffer; ASN1 or PEM.
   --  Please see the examples for proper usage.

   function Use_Private_Key_File (Context : Context_Type;
                                  File    : String;
                                  Format  : File_Format)
                                  return Subprogram_Result with
      Pre => Is_Valid (Context);
   --  This function loads a private key file into the SSL context.
   --  The file is provided by the File argument. The Format argument
   --  specifies the format type of the file - ASN1 or PEM.
   --  Please see the examples for proper usage.

   function Use_Private_Key_Buffer (Context : Context_Type;
                                    Input   : Byte_Array;
                                    Format  : File_Format)
                                    return Subprogram_Result with
      Pre => Is_Valid (Context);
   --  This function loads a private key buffer into the SSL Context.
   --  It behaves like the non-buffered version (Use_Private_Key_File),
   --  only differing in its ability to be called with a buffer as input
   --  instead of a file. The buffer is provided by the Input argument.
   --  Format specifies the format type of the buffer; ASN1 or PEM.
   --  Please see the examples for proper usage.

   function Load_Verify_Locations (Context : Context_Type;
                                   File    : String;
                                   Path    : String)
                                   return Subprogram_Result with
      Pre => Is_Valid (Context);
   --  This function loads PEM-formatted CA certificate files into
   --  the SSL context. These certificates will be treated as trusted
   --  root certificates and used to verify certs received from peers
   --  during the SSL handshake. The root certificate file,
   --  provided by the File argument, may be a single certificate or
   --  a file containing multiple certificates. If multiple CA certs
   --  are included in the same file, wolfSSL will load them in the same
   --  order they are presented in the file. The path argument is
   --  a pointer to the name of a directory that contains certificates
   --  of trusted root CAs. If the value of File is not empty "",
   --  path may be specified as "" if not needed. If path is specified
   --  and NO_WOLFSSL_DIR was not defined when building the library,
   --  wolfSSL will load all CA certificates located in the given
   --  directory. This function will attempt to load all files in
   --  the directory. This function expects PEM formatted CERT_TYPE file
   --  with header "--BEGIN CERTIFICATE--".

   function Load_Verify_Buffer (Context : Context_Type;
                                Input   : Byte_Array;
                                Format  : File_Format)
                                return Subprogram_Result with
      Pre => Is_Valid (Context);
   --  This function loads a CA certificate buffer into the SSL
   --  Context. It behaves like the non-buffered version, only differing
   --  in its ability to be called with a buffer as input instead of
   --  a file. The buffer is provided by the Input argument.
   --  Format specifies the format type of the buffer; ASN1 or PEM.
   --  More than one CA certificate may be loaded
   --  per buffer as long as the format is in PEM.
   --  Please see the examples for proper usage.

   type WolfSSL_Type is limited private with
     Annotate => (GNATprove, Ownership, "Needs_Reclamation");
   --  Instances of this type are called SSL Sessions.

   function Is_Valid (Ssl : WolfSSL_Type) return Boolean with
      Annotate => (GNATprove, Ownership, "Needs_Reclamation");
   --  Indicates if the SSL Session has successfully been initialized.
   --  If initialized, the SSL Session has allocated resources
   --  that needs to be deallocated before application exit.
   --  Annotation added for GNATprove ownership analysis.
   --    https://docs.adacore.com/spark2014-docs/html/ug/en/appendix/additional_annotate_pragmas.html#annotation-for-enforcing-ownership-checking-on-a-private-type

   procedure Create_WolfSSL (Context : Context_Type;
                             Ssl     : out WolfSSL_Type) with
      Pre => Is_Valid (Context);
   --  This function creates a new SSL session, taking an already created
   --  SSL context as input.
   --  If successful Is_Valid (Ssl) = True, otherwise False.

   function Use_Certificate_File (Ssl     : WolfSSL_Type;
                                  File    : String;
                                  Format  : File_Format)
                                  return Subprogram_Result with
      Pre => Is_Valid (Ssl);
   --  This function loads a certificate file into the SSL session.
   --  The certificate file is provided by the file argument.
   --  The format argument specifies the format type of the file
   --  either ASN1 or PEM.

   function Use_Certificate_Buffer (Ssl     : WolfSSL_Type;
                                    Input   : Byte_Array;
                                    Format  : File_Format)
                                    return Subprogram_Result with
      Pre => Is_Valid (Ssl);
   --  This function loads a certificate buffer into the SSL session
   --  object. It behaves like the non-buffered version, only differing
   --  in its ability to be called with a buffer as input instead
   --  of a file. The buffer is provided by the Input argument.
   --  Format specifies the format type of the buffer; ASN1 or PEM.
   --  Please see the examples for proper usage.

   function Use_Private_Key_File (Ssl     : WolfSSL_Type;
                                  File    : String;
                                  Format  : File_Format)
                                  return Subprogram_Result with
      Pre => Is_Valid (Ssl);
   --  This function loads a private key file into the SSL session.
   --  The key file is provided by the File argument. The Format argument
   --  specifies the format type of the file - ASN1 or PEM.

   function Use_Private_Key_Buffer (Ssl     : WolfSSL_Type;
                                    Input   : Byte_Array;
                                    Format  : File_Format)
                                    return Subprogram_Result with
      Pre => Is_Valid (Ssl);
   --  This function loads a private key buffer into the SSL session
   --  object. It behaves like the non-buffered version, only differing
   --  in its ability to be called with a buffer as input instead
   --  of a file. The buffer is provided by the Input argument.
   --  Format specifies the format type of the buffer; ASN1 or PEM.
   --  Please see the examples for proper usage.

   function Attach (Ssl    : WolfSSL_Type;
                    Socket : Integer)
                    return Subprogram_Result with
      Pre => Is_Valid (Ssl);
   --  Attach wolfSSL to the socket.
   --
   --  This function assigns a file descriptor (Socket) as
   --  the input/output facility for the SSL connection.
   --  Typically this will be a socket file descriptor.

   procedure Keep_Arrays (Ssl : WolfSSL_Type) with
      Pre => Is_Valid (Ssl);
   --  Normally, at the end of the SSL handshake, wolfSSL frees
   --  temporary arrays. Calling this function before the handshake
   --  begins will prevent wolfSSL from freeing temporary arrays.
   --  Temporary arrays may be needed for things such as
   --  wolfSSL_get_keys() or PSK hints. When the user is done with
   --  temporary arrays, either Free_Arrays(..) may be called to free
   --  the resources immediately, or alternatively the resources will
   --  be freed when the associated SSL object is freed.

   procedure Free_Arrays (Ssl : WolfSSL_Type) with
      Pre => Is_Valid (Ssl);
   --  Normally, at the end of the SSL handshake, wolfSSL frees temporary
   --  arrays. If Keep_Arrays(..) has been called before the handshake,
   --  wolfSSL will not free temporary arrays. This function explicitly
   --  frees temporary arrays and should be called when the user is done
   --  with temporary arrays and does not want to wait for the SSL object
   --  to be freed to free these resources.

   function Accept_Connection (Ssl : WolfSSL_Type)
                               return Subprogram_Result with
      Pre => Is_Valid (Ssl);
   --  The name of this function is not Accept (..) because the word
   --  "accept" is a reserved keyword in the Ada language.
   --
   --  This function is called on the server side and waits for an
   --  SSL client to initiate the SSL/TLS handshake. When this function
   --  is called, the underlying communication channel has already been
   --  set up. This function works with both blocking and
   --  non-blocking I/O. When the underlying I/O is non-blocking,
   --  Accept_Connection (..) will return when the underlying I/O could
   --  not satisfy the needs of Accept_Connection (..) to continue
   --  the handshake. In this case, a call to Get_Error(..) will
   --  yield either Error_Want_Read or Error_Want_Write.
   --  The calling process must then repeat the call to
   --  Accept_Connection (..) when data is available to read and
   --  wolfSSL will pick up where it left off. When using a
   --  non_blocking socket, nothing needs to be done, but select() can
   --  be used to check for the required condition.
   --  If the underlying I/O is blocking, Accept_Connection (..) will
   --  only return once the handshake has been finished or
   --  an error occurred.

   --  This record type has discriminants with default values to be able
   --  to compile this code under the restriction No Secondary Stack.
   type Read_Result (Success : Boolean := False;
                     Last    : Byte_Index := Byte_Index'Last) is record
      case Success is
         when True  => Buffer : Byte_Array (1 .. Last);
         when False => Code : Subprogram_Result; --  Error code
      end case;
   end record;

   procedure Read (Ssl : WolfSSL_Type;
                   Result : out Read_Result) with
      Pre => Is_Valid (Ssl);
   --  This function reads a number of bytes from the SSL session (ssl)
   --  internal read buffer into the buffer data. The bytes read are
   --  removed from the internal receive buffer.
   --  If necessary Read(..) will negotiate an SSL/TLS session
   --  if the handshake has not already
   --  been performed yet by Connect(..) or Accept_Connection (..).
   --  The SSL/TLS protocol uses SSL records which have a maximum size
   --  of 16kB (the max record size can be controlled by the
   --  MAX_RECORD_SIZE define in /wolfssl/internal.h). As such, wolfSSL
   --  needs to read an entire SSL record internally before it is able
   --  to process and decrypt the record. Because of this, a call to
   --  Read(..) will only be able to return the maximum buffer
   --  size which has been decrypted at the time of calling. There may
   --  be additional not-yet-decrypted data waiting in the internal
   --  wolfSSL receive buffer which will be retrieved and decrypted with
   --  the next call to Read(..).

   --  This record type has discriminants with default values to be able
   --  to compile this code under the restriction No Secondary Stack.
   type Write_Result (Success : Boolean := False) is record
      case Success is
         when True  => Bytes_Written : Byte_Index;
         when False => Code : Subprogram_Result; --  Error code
      end case;
   end record;

   procedure Write (Ssl  : WolfSSL_Type;
                    Data : Byte_Array;
                    Result : out Write_Result) with
      Pre => Is_Valid (Ssl);
   --  The number of bytes written is returned.
   --  This function writes bytes from the buffer, Data,
   --  to the SSL connection, ssl. If necessary, Write(..) will
   --  negotiate an SSL/TLS session if the handshake has not already
   --  been performed yet by Connect(..) or Accept_Connection(..).
   --  Write(..) works with both blocking and non-blocking I/O.
   --  When the underlying I/O is non-blocking, Write(..) will return
   --  when the underlying I/O could not satisfy the needs of Write(..)
   --  to continue. In this case, a call to Get_Error(..) will
   --  yield either Error_Want_Read or Error_Want_Write.
   --  The calling process must then repeat the call to Write(..)
   --  when the underlying I/O is ready. If the underlying I/O is
   --  blocking, Write(..) will only return once the buffer data
   --  has been completely written or an error occurred.

   function Shutdown (Ssl : WolfSSL_Type) return Subprogram_Result with
      Pre => Is_Valid (Ssl);
   --  This function shuts down an active SSL/TLS connection using
   --  the SSL session, ssl. This function will try to send a
   --  "close notify" alert to the peer. The calling application can
   --  choose to wait for the peer to send its "close notify" alert
   --  in response or just go ahead and shut down the underlying
   --  connection after directly calling wolfSSL_shutdown (to save
   --  resources). Either option is allowed by the TLS specification.
   --  If the underlying connection will be used again in the future,
   --  the complete two_directional shutdown procedure must be performed
   --  to keep synchronization intact between the peers.
   --  Shutdown(..) works with both blocking and non_blocking I/O.
   --  When the underlying I/O is non_blocking, Shutdown(..) will
   --  return an error if the underlying I/O could not satisfy the needs
   --  of Shutdown(..) to continue. In this case, a call to
   --  Get_Error(..) will yield either Error_Want_Read or
   --  Error_Want_Write. The calling process must then repeat
   --  the call to Shutdown() when the underlying I/O is ready.

   procedure Free (Ssl : in out WolfSSL_Type) with
      Post => not Is_Valid (Ssl);
   --  Frees the resources allocated by the SSL session object.
   --  If Ssl is not valid, this is a no-op.

   function Connect (Ssl : WolfSSL_Type) return Subprogram_Result with
      Pre => Is_Valid (Ssl);
   --  This function is called on the client side and initiates
   --  an SSL/TLS handshake with a server. When this function is called,
   --  the underlying communication channel has already been set up.
   --  Connect(..) works with both blocking and non_blocking I/O.
   --  When the underlying I/O is non_blocking, Connect(..) will
   --  return when the underlying I/O could not satisfy the needs
   --  of wolfSSL_connect to continue the handshake. In this case,
   --  a call to Get_Error(..) will yield either
   --  Error_Want_Read or SSL_ERROR_WANT_WRITE. The calling process
   --  must then repeat the call to Connect(..) when
   --  the underlying I/O is ready and wolfSSL will pick up where
   --  it left off. When using a non_blocking socket, nothing needs
   --  to be done, but select() can be used to check for the required
   --  condition. If the underlying I/O is blocking, Connect(..)
   --  will only return once the handshake has been finished or an error
   --  occurred. wolfSSL takes a different approach to certificate
   --  verification than OpenSSL does. The default policy for the client
   --  is to verify the server, this means that if you don't load CAs
   --  to verify the server you'll get a connect error,
   --  unable to verify. It you want to mimic OpenSSL behavior
   --  of having SSL_connect succeed even if verifying the server fails
   --  and reducing security you can do this by calling:
   --  Set_Verify (Ctx, Verify_None, 0); before calling
   --  Create_WolfSSL(...); Though it's not recommended.

   type Error_Code is new Integer;

   Error_Want_Read  : constant Error_Code;
   Error_Want_Write : constant Error_Code;

   function Get_Error (Ssl    : WolfSSL_Type;
                       Result : Subprogram_Result) return Error_Code;
   --  This function returns a unique error code describing why
   --  the previous API function call (Connect, Accept_Connection,
   --  Read, Write, etc.) resulted in an error return code.
   --  After Get_Error is called and returns the unique error code,
   --  wolfSSL_ERR_error_string() may be called to get a human readable
   --  error string.

   subtype Error_Message_Index is Natural range 0 .. 80;
   --  The default error message length is 80 in WolfSSL unless
   --  configured to another value. See the result
   --  of the Max_Error_Size function.

   type Error_Message (Last : Error_Message_Index := 0) is record
      Text : String (1 .. Last);
   end record;

   procedure Error (Code    : in  Error_Code;
                    Message : in out Error_Message);
   --  This function converts an error code returned by Get_Error(..)
   --  into a more human readable error string. Code is the error code
   --  returned by Get_error(). The maximum length of error strings is
   --  80 characters by default, as defined by MAX_ERROR_SZ
   --  is wolfssl/wolfcrypt/error.h.
   --
   --  If Message has not been updated with a text, it may be because
   --  an exception was raised during the execution of the subprogram.

   function Max_Error_Size return Natural;
   --  Returns the value of the defined MAX_ERROR_SZ integer
   --  in wolfssl/wolfcrypt/error.h.

   type RNG_Type is limited private with
     Annotate => (GNATprove, Ownership, "Needs_Reclamation");

   function Is_Valid (Key : RNG_Type) return Boolean with
      Annotate => (GNATprove, Ownership, "Needs_Reclamation");
   --  Indicates if the RNG has successfully been initialized.
   --  Annotation added for GNATprove ownership analysis.
   --    https://docs.adacore.com/spark2014-docs/html/ug/en/appendix/additional_annotate_pragmas.html#annotation-for-enforcing-ownership-checking-on-a-private-type

   procedure Create_RNG (Key    : in out RNG_Type;
                         Result : out Integer) with
     Pre => not Is_Valid (Key),
     Post => (if Result = 0 then Is_Valid (Key));
   --  If successful Result = 0.

   procedure Free_RNG (Key : in out RNG_Type) with
     Pre => Is_Valid (Key),
     Post => not Is_Valid (Key);
   --  Frees resources associated with RNG and releases the underlying C object.

   procedure RNG_Generate_Block (RNG    : RNG_Type;
                                 Output : out Byte_Array;
                                 Result : out Integer) with
     Pre => Is_Valid (RNG);

   type HMAC_Hash is (MD5, SHA, SHA256, SHA384, SHA512, SHA3_224,
                      SHA3_256, SHA3_384, SHA3_512);

   procedure PBKDF2 (Output     : out Byte_Array;
                     Password   : Byte_Array;
                     Salt       : Byte_Array;
                     Iterations : Positive;
                     Key_Length : Positive;
                     HMAC       : HMAC_Hash;
                     Result     : out Integer);

   type RSA_Key_Type is limited private with
     Annotate => (GNATprove, Ownership, "Needs_Reclamation");

   function Is_Valid (Key : RSA_Key_Type) return Boolean with
      Annotate => (GNATprove, Ownership, "Needs_Reclamation");
   --  Indicates if the RSA has successfully been initialized.
   --  Annotation added for GNATprove ownership analysis.
   --    https://docs.adacore.com/spark2014-docs/html/ug/en/appendix/additional_annotate_pragmas.html#annotation-for-enforcing-ownership-checking-on-a-private-type

   procedure Create_RSA (Key    : in out RSA_Key_Type;
                         Result : out Integer) with
     Pre => not Is_Valid (Key),
     Post => (if Result = 0 then Is_Valid (Key));
   --  If successful Result = 0.

   procedure Free_RSA (Key : in out RSA_Key_Type) with
     Pre => Is_Valid (Key),
     Post => not Is_Valid (Key);
   --  Frees resources associated with RSA and releases the underlying C object.

   procedure Rsa_Public_Key_Decode (Input : Byte_Array;
                                    Index : in out Byte_Index;
                                    Key   : in out RSA_Key_Type;
                                    Size  : Integer;
                                    Result : out Integer) with
     Pre => Is_Valid (Key);
   --  This function parses a DER-formatted RSA public key,
   --  extracts the public key and stores it in the RsaKey structure
   --  specified by the Key input argument. It also sets the distance
   --  parsed in Index.
   --  Note: A RsaKey structure contains two parts,
   --        one public and one private key.

   procedure Rsa_Private_Key_Decode (Input : Byte_Array;
                                     Index : in out Byte_Index;
                                     Key   : in out RSA_Key_Type;
                                     Size  : Integer;
                                     Result : out Integer) with
     Pre => Is_Valid (Key);
   --  This function parses a DER-formatted RSA private key,
   --  extracts the private key and stores it in the RsaKey structure
   --  specified by the Key input argument. It also sets the distance
   --  parsed in Index.
   --  Note: A RsaKey structure contains two parts,
   --        one public and one private key.

   procedure Rsa_Set_RNG (Key    : in out Rsa_Key_Type;
                          RNG    : in out RNG_Type;
                          Result : out Integer);

   procedure Rsa_SSL_Sign (Input  : Byte_Array;
                           Output : in out Byte_Array;
                           RSA    : in out RSA_Key_Type;
                           RNG    : in out RNG_Type;
                           Result : out Integer) with
     Pre => Is_Valid (RSA) and Is_Valid (RNG);
   --  The Output buffer must have the same size as the RSA key.
   --  If successful Result = 0.
   --  If Result < 0, then failure.
   --  If Result > 0, then Success and is the size of the RSA key in bytes.

   procedure Rsa_SSL_Verify (Input  : Byte_Array;
                             Output : in out Byte_Array;
                             RSA    : in out RSA_Key_Type;
                             Result : out Integer) with
     Pre => Is_Valid (RSA);
   --  If Result < 0, then failure.
   --  If Result > 0, then digital signature in Input
   --                 successfully verified.

   procedure RSA_Public_Encrypt (Input  : Byte_Array;
                                 Output : in out Byte_Array;
                                 Index  :    out Byte_Index;
                                 RSA    : in out RSA_Key_Type;
                                 RNG    : in out RNG_Type;
                                 Result :    out Integer) with
     Pre => Is_Valid (RSA);
   --  This function encrypts a message from Input and stores the result
   --  in Output. It requires an initialized public key and a random
   --  number generator. As a side effect, this function will return
   --  the bytes written to Output in Index.

   procedure RSA_Private_Decrypt (Input  : Byte_Array;
                                  Output : in out Byte_Array;
                                  Index  :    out Byte_Index;
                                  RSA    : in out RSA_Key_Type;
                                  Result :    out Integer) with
     Pre => Is_Valid (RSA);
   --  This functions provides private RSA decryption.

   type SHA256_Type is limited private with
     Annotate => (GNATprove, Ownership, "Needs_Reclamation");

   function Is_Valid (SHA256 : SHA256_Type) return Boolean with
      Annotate => (GNATprove, Ownership, "Needs_Reclamation");
   --  Indicates if the SHA256 has successfully been initialized.
   --  Annotation added for GNATprove ownership analysis.
   --    https://docs.adacore.com/spark2014-docs/html/ug/en/appendix/additional_annotate_pragmas.html#annotation-for-enforcing-ownership-checking-on-a-private-type

   procedure Create_SHA256 (SHA256 : in out SHA256_Type;
                            Result : out Integer) with
     Pre  => not Is_Valid (SHA256),
     Post => (if Result = 0 then Is_Valid (SHA256));
   --  If successful Result = 0.

   procedure Free_SHA256 (SHA256 : in out SHA256_Type) with
     Pre  => Is_Valid (SHA256),
     Post => not Is_Valid (SHA256);
   --  Frees resources associated with SHA256 and releases the underlying C object.
   --  If successful Result = 0.

   procedure Update_SHA256 (SHA256 : in out SHA256_Type;
                            Byte   : Byte_Array;
                            Result : out Integer) with
     Pre => Is_Valid (SHA256);
   --  If successful Result = 0.

   subtype SHA256_As_String is String (1 .. 64);

   subtype SHA256_Hash is Byte_Array (1 .. 32);

   procedure Finalize_SHA256 (SHA256 : in out SHA256_Type;
                              Hash   : out SHA256_Hash;
                              Result : out Integer) with
     Pre => Is_Valid (SHA256);
   --  If successful Result = 0.

   type Device_Identifier is new Integer;

   function Invalid_Device return Device_Identifier;

   type AES_Type is limited private with
     Annotate => (GNATprove, Ownership, "Needs_Reclamation");

   function Is_Valid (AES : AES_Type) return Boolean with
      Annotate => (GNATprove, Ownership, "Needs_Reclamation");
   --  Indicates if the AES has successfully been initialized.
   --  Annotation added for GNATprove ownership analysis.
   --    https://docs.adacore.com/spark2014-docs/html/ug/en/appendix/additional_annotate_pragmas.html#annotation-for-enforcing-ownership-checking-on-a-private-type

   procedure Create_AES (Device : Device_Identifier;
                         AES    : in out AES_Type;
                         Result : out Integer) with
     Pre  => not Is_Valid (AES),
     Post => (if Result = 0 then Is_Valid (AES));
   --  If successful Is_Valid (AES) = True, and Result = 0.

   procedure AES_Free (AES : in out AES_Type;
                       Result : out Integer) with
     Pre  => Is_Valid (AES),
     Post => (if Result = 0 then not Is_Valid (AES));
   --  Frees resources associated with AES and releases the underlying C object.

   procedure AES_Set_Key (AES    : AES_Type;
                          Key    : Byte_Array;
                          Length : Integer;
                          IV     : Byte_Array;
                          Dir    : Integer;
                          Result : out Integer) with
     Pre => Is_Valid (AES);

   procedure AES_Set_IV (AES : AES_Type;
                         IV  : Byte_Array;
                         Result : out Integer) with
     Pre => Is_Valid (AES);

   procedure AES_Set_Cbc_Encrypt (AES : AES_Type;
                                  Output : out Byte_Array;
                                  Input : Byte_Array;
                                  Size : Integer;
                                  Result : out Integer) with
     Pre => Is_Valid (AES);

   procedure AES_Set_Cbc_Decrypt (AES : AES_Type;
                                  Output : out Byte_Array;
                                  Input : Byte_Array;
                                  Size : Integer;
                                  Result : out Integer) with
     Pre => Is_Valid (AES);

   --  (Removed duplicate AES_Free declaration)

private
   pragma SPARK_Mode (Off);

   type chars_ptr is access all Character;
   pragma Convention (C, chars_ptr);

   pragma No_Strict_Aliasing (chars_ptr);
   --  Since this type is used for external interfacing, with the pointer
   --  coming from who knows where, it seems a good idea to turn off any
   --  strict aliasing assumptions for this type.

   subtype int is Interfaces.C.int; use type int;

   type Opaque_Method  is limited null record;
   type Opaque_Context is limited null record;
   type Opaque_WolfSSL is limited null record;

   --  Access-to-object types with convention C uses the same amount of
   --  memory for storing pointers as is done in the C programming
   --  language. The following access type definitions are used in
   --  the Ada binding to the WolfSSL library:
   type Context_Type is access Opaque_Context with Convention => C;
   type Method_Type  is access Opaque_Method  with Convention => C;
   type WolfSSL_Type is access Opaque_WolfSSL with Convention => C;

   subtype Unsigned_32 is Interfaces.Unsigned_32; use type Unsigned_32;

   type Mode_Type is new Unsigned_32;

   --  The following imported subprograms are used to initialize
   --  the constants defined in the public part of this package
   --  specification. They cannot therefore be moved to the body
   --  of this package.

   function WolfSSL_Verify_None return int with
     Convention    => C,
     External_Name => "get_wolfssl_verify_none",
     Import        => True;

   function WolfSSL_Verify_Peer return int with
     Convention    => C,
     External_Name => "get_wolfssl_verify_peer",
     Import        => True;

   function WolfSSL_Verify_Fail_If_No_Peer_Cert return int with
     Convention    => C,
     External_Name => "get_wolfssl_verify_fail_if_no_peer_cert",
     Import        => True;

   function WolfSSL_Verify_Client_Once return int with
     Convention    => C,
     External_Name => "get_wolfssl_verify_client_once",
     Import        => True;

   function WolfSSL_Verify_Post_Handshake return int with
     Convention    => C,
     External_Name => "get_wolfssl_verify_post_handshake",
     Import        => True;

   function WolfSSL_Verify_Fail_Except_Psk return int with
     Convention    => C,
     External_Name => "get_wolfssl_verify_fail_except_psk",
     Import        => True;

   function WolfSSL_Verify_Default return int with
     Convention    => C,
     External_Name => "get_wolfssl_verify_default",
     Import        => True;

   pragma Warnings (Off, "pragma Restrictions (No_Exception_Propagation)");
   --  The compiler may check for warnings related to no exception
   --  propagation if this code is compiled with the Zero
   --  Footprint run-time. The constants exposed here in the Ada binding
   --  have valid values defined in the WolfSSL library but the compiler
   --  cannot know this since the values become known during run-time.

   Verify_None : constant Mode_Type := Mode_Type (WolfSSL_Verify_None);
   Verify_Peer : constant Mode_Type := Mode_Type (WolfSSL_Verify_Peer);

   Verify_Fail_If_No_Peer_Cert : constant Mode_Type :=
     Mode_Type (WolfSSL_Verify_Fail_If_No_Peer_Cert);

   Verify_Client_Once : constant Mode_Type :=
     Mode_Type (WolfSSL_Verify_Client_Once);

   Verify_Post_Handshake : constant Mode_Type :=
     Mode_Type (WolfSSL_Verify_Post_Handshake);

   Verify_Fail_Except_Psk : constant Mode_Type :=
     Mode_Type (WolfSSL_Verify_Fail_Except_Psk);

   Verify_Default : constant Mode_Type :=
     Mode_Type (WolfSSL_Verify_Default);
   pragma Warnings (On, "pragma Restrictions (No_Exception_Propagation)");

   type File_Format is new Unsigned_32;

   function WolfSSL_Filetype_Asn1 return int with
     Convention    => C,
     External_Name => "get_wolfssl_filetype_asn1",
     Import        => True;

   function WolfSSL_Filetype_Pem return int with
     Convention    => C,
     External_Name => "get_wolfssl_filetype_pem",
     Import        => True;

   function WolfSSL_Filetype_Default return int with
     Convention    => C,
     External_Name => "get_wolfssl_filetype_default",
     Import        => True;

   pragma Warnings (Off, "pragma Restrictions (No_Exception_Propagation)");
   --  The compiler may check for warnings related to no exception
   --  propagation if this code is compiled with the Zero
   --  Footprint run-time. The constants exposed here in the Ada binding
   --  have valid values defined in the WolfSSL library but the compiler
   --  cannot know this since the values become known during run-time.
   Format_Asn1 : constant File_Format :=
     File_Format (WolfSSL_Filetype_Asn1);

   Format_Pem : constant File_Format :=
     File_Format (WolfSSL_Filetype_Pem);

   Format_Default : constant File_Format :=
     File_Format (WolfSSL_Filetype_Default);
   pragma Warnings (On, "pragma Restrictions (No_Exception_Propagation)");

   function Get_WolfSSL_Success return int with
     Convention    => C,
     External_Name => "get_wolfssl_success",
     Import        => True;

   function Get_WolfSSL_Failure return int with
     Convention    => C,
     External_Name => "get_wolfssl_failure",
     Import        => True;

   Success : constant Subprogram_Result :=
      Subprogram_Result (Get_WolfSSL_Success);
   --  Indicates success for some functions.
   --  Do not use, unless you know what you do.

   Failure : constant Subprogram_Result :=
     Subprogram_Result (Get_WolfSSL_Failure);

   function Get_WolfSSL_Error_Want_Read return int with
     Convention    => C,
     External_Name => "get_wolfssl_error_want_read",
     Import        => True;

   function Get_WolfSSL_Error_Want_Write return int with
     Convention    => C,
     External_Name => "get_wolfssl_error_want_write",
     Import        => True;

   Error_Want_Read  : constant Error_Code :=
      Error_Code (Get_WolfSSL_Error_Want_Read);

   Error_Want_Write : constant Error_Code :=
     Error_Code (Get_WolfSSL_Error_Want_Write);

   type Opaque_RNG is limited null record;
   type RNG_Type is access Opaque_RNG with Convention => C;

   type Opaque_RSA is limited null record;
   type RSA_Key_Type is access Opaque_RSA with Convention => C;

   type Opaque_Sha256 is limited null record;
   type SHA256_Type is access Opaque_Sha256 with Convention => C;

   type Opaque_AES is limited null record;
   type AES_Type is access Opaque_AES with Convention => C;

end WolfSSL;
