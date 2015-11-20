using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace wolfSSL.CSharp {
    public class wolfssl
    {
        private const string wolfssl_dll = "wolfssl.dll";

        /********************************
         * Class for DTLS connections
         */
        public class DTLS_con
        {
            public UdpClient udp;
            public IPEndPoint ep;
        }


        /********************************
         * Init wolfSSL library
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_Init();
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_Cleanup();


        /********************************
         * Methods of connection
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfTLSv1_2_server_method();
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfSSLv23_server_method();
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfTLSv1_2_client_method();
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfSSLv23_client_method();
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfDTLSv1_2_server_method();
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfDTLSv1_2_client_method();


        /********************************
         * Call backs
         */
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int CallbackIORecv_delegate(IntPtr ssl, IntPtr buf, int sz, IntPtr ctx);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_SetIORecv(IntPtr ctx, CallbackIORecv_delegate recv);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_SetIOReadCtx(IntPtr ssl, IntPtr rctx);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfSSL_GetIOReadCtx(IntPtr ssl);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int CallbackIOSend_delegate(IntPtr ssl, IntPtr buf, int sz, IntPtr ctx);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_SetIOSend(IntPtr ctx, CallbackIOSend_delegate send);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_SetIOWriteCtx(IntPtr ssl, IntPtr wctx);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfSSL_GetIOWriteCtx(IntPtr ssl);


        /********************************
         * CTX structure
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfSSL_CTX_new(IntPtr method);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_CTX_use_certificate_file(IntPtr ctx, string file, int type);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_CTX_use_PrivateKey_file(IntPtr ctx, string file, int type);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static void wolfSSL_CTX_free(IntPtr ctx);


        /********************************
         * PSK
         */
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate uint psk_delegate(IntPtr ssl, string identity, IntPtr key, uint max_sz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static void wolfSSL_set_psk_server_callback(IntPtr ssl, psk_delegate psk_cb);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static void wolfSSL_CTX_set_psk_server_callback(IntPtr ctx, psk_delegate psk_cb);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_CTX_use_psk_identity_hint(IntPtr ctx, StringBuilder identity);


        /********************************
         * SSL Structure
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfSSL_new(IntPtr ctx);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_accept(IntPtr ssl);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_connect(IntPtr ssl);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_read(IntPtr ssl, StringBuilder buf, int sz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_write(IntPtr ssl, StringBuilder buf, int sz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_shutdown(IntPtr ssl);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static void wolfSSL_free(IntPtr ssl);


        /********************************
         * Cipher lists
         */
        /* only supports full name from cipher_name[] delimited by : */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_CTX_set_cipher_list(IntPtr ctx, StringBuilder ciphers);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_set_cipher_list(IntPtr ssl, StringBuilder ciphers);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_get_ciphers(StringBuilder ciphers, int sz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfSSL_get_cipher(IntPtr ssl);
        [DllImport(wolfssl_dll, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfSSL_CIPHER_get_name(IntPtr cipher);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfSSL_get_current_cipher(IntPtr ssl);
        [DllImport(wolfssl_dll, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfSSL_get_version(IntPtr ssl);
        [DllImport(wolfssl_dll, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfSSL_get_cipher_list(IntPtr ssl);


        /********************************
         * Error logging
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr wolfSSL_ERR_error_string(int err, StringBuilder errOut);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_get_error(IntPtr ssl, int err);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void loggingCb(int lvl, StringBuilder msg);
        private static loggingCb internal_log;


        /********************************
         * DH
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_CTX_SetMinDhKey_Sz(IntPtr ctx, short size);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        public extern static int wolfSSL_SetTmpDH_file(IntPtr ssl, StringBuilder dhParam, int type);


        /********************************
         * Enum types from wolfSSL library
         */
        public static readonly int SSL_FILETYPE_PEM = 1;
        public static readonly int SSL_FILETYPE_ASN1= 2;
        public static readonly int SSL_FILETYPE_RAW = 3;
        public static readonly int CBIO_ERR_GENERAL    = -1;
        public static readonly int CBIO_ERR_WANT_READ  = -2;
        public static readonly int CBIO_ERR_WANT_WRITE = -2;
        public static readonly int CBIO_ERR_CONN_RST   = -3;
        public static readonly int CBIO_ERR_ISR        = -4;
        public static readonly int CBIO_ERR_CONN_CLOSE = -5;
        public static readonly int CBIO_ERR_TIMEOUT    = -6;

        public static readonly int SUCCESS = 1;
        public static readonly int FAILURE = 0;


        /// <summary>
        /// Call back to allow recieving TLS information
        /// </summary>
        /// <param name="ssl">structure of ssl passed in</param>
        /// <param name="buf">buffer to contain recieved msg</param>
        /// <param name="sz">size of buffer</param>
        /// <param name="ctx">optional information passed in</param>
        /// <returns>size of message recieved</returns>
        private static int wolfSSLCbIORecv(IntPtr ssl, IntPtr buf, int sz, IntPtr ctx)
        {
            if (sz <= 0)
            {
                log(1, "wolfssl recieve error, size less than 0");
                return wolfssl.CBIO_ERR_GENERAL;
            }

            int amtRecv = 0;

            System.Runtime.InteropServices.GCHandle gch;
            gch = GCHandle.FromIntPtr(ctx);
            Socket con = (System.Net.Sockets.Socket)gch.Target;

            try
            {
                Byte[] msg = new Byte[sz];
                amtRecv = con.Receive(msg, msg.Length, 0);
                Marshal.Copy(msg, 0, buf, sz);
            }
            catch (Exception e)
            {
                log(1, "Error in recive " + e.ToString());
                return wolfssl.CBIO_ERR_CONN_CLOSE;
            }

            return amtRecv;
        }


        /// <summary>
        /// Call back used for sending TLS information
        /// </summary>
        /// <param name="ssl">pointer to ssl struct</param>
        /// <param name="buf">buffer containing information to send</param>
        /// <param name="sz">size of buffer to send</param>
        /// <param name="ctx">optional information</param>
        /// <returns>amount of information sent</returns>
        private static int wolfSSLCbIOSend(IntPtr ssl, IntPtr buf, int sz, IntPtr ctx)
        {
            if (sz <= 0)
            {
                log(1, "wolfssl send error, size less than 0");
                return wolfssl.CBIO_ERR_GENERAL;
            }

            System.Runtime.InteropServices.GCHandle gch;
            gch = GCHandle.FromIntPtr(ctx);

            Socket con = (System.Net.Sockets.Socket)gch.Target;

            Byte[] msg = new Byte[sz];

            Marshal.Copy(buf, msg, 0, sz);
            try
            {
                con.Send(msg, 0, msg.Length, SocketFlags.None);
                return sz;
            }
            catch (Exception e)
            {
                log(1, "socket connection issue "+ e.ToString());
                return wolfssl.CBIO_ERR_CONN_CLOSE;
            }
        }

        
        /// <summary>
        /// Call back used for sending DTLS information
        /// </summary>
        /// <param name="ssl">pointer to ssl struct</param>
        /// <param name="buf">buffer containing information to send</param>
        /// <param name="sz">size of buffer to send</param>
        /// <param name="ctx">optional information</param>
        /// <returns>amount of information sent</returns>
        private static int wolfSSL_dtlsCbIOSend(IntPtr ssl, IntPtr buf, int sz, IntPtr ctx)
        {
            if (sz <= 0)
            {
                log(1, "wolfssl dtls send error, size less than 0");
                return wolfssl.CBIO_ERR_GENERAL;
            }

            System.Runtime.InteropServices.GCHandle gch;
            gch = GCHandle.FromIntPtr(ctx);

            DTLS_con con = (DTLS_con)gch.Target;

            Byte[] msg = new Byte[sz];

            Marshal.Copy(buf, msg, 0, sz);
            try
            {
                con.udp.Send(msg, msg.Length, con.ep);
                return msg.Length;
            }
            catch (Exception e)
            {
                log(1, "socket connection issue " + e.ToString());
                return wolfssl.CBIO_ERR_CONN_CLOSE;
            }
        }

        
        /// <summary>
        /// Call back to allow recieving DTLS information
        /// </summary>
        /// <param name="ssl">structure of ssl passed in</param>
        /// <param name="buf">buffer to contain recieved msg</param>
        /// <param name="sz">size of buffer</param>
        /// <param name="ctx">optional information passed in</param>
        /// <returns>size of message recieved</returns>
        private static int wolfSSL_dtlsCbIORecv(IntPtr ssl, IntPtr buf, int sz, IntPtr ctx)
        {

            if (sz <= 0)
            {
                log(1, "wolfssl dtls recieve error, size less than 0");
                return wolfssl.CBIO_ERR_GENERAL;
            }

            System.Runtime.InteropServices.GCHandle gch;
            gch = GCHandle.FromIntPtr(ctx);
            DTLS_con con = (DTLS_con)gch.Target;

            Byte[] msg = new Byte[sz];
            try
            {
                msg = con.udp.Receive(ref con.ep);
            }
            catch (Exception e)
            {
                /* issue with receive or size of buffer */
                log(1, "socket read issue "+ e.ToString());
                return wolfssl.CBIO_ERR_CONN_CLOSE;
            }

            Marshal.Copy(msg, 0, buf, msg.Length);

            return msg.Length;
        }


        /// <summary>
        /// Create a new ssl structure
        /// </summary>
        /// <param name="ctx">structure to create ssl structure from</param>
        /// <returns>pointer to ssl structure</returns>
        public static IntPtr new_ssl(IntPtr ctx)
        {
            try
            {
                return wolfSSL_new(ctx);
            }
            catch (Exception e)
            {
                log(1, e.ToString());
                return IntPtr.Zero;
            }
        }


        /// <summary>
        /// Used for a server to accept a connection
        /// </summary>
        /// <param name="ssl">structure containing info for connection</param>
        /// <returns>1 on success</returns>
        public static int accept(IntPtr ssl)
        {
            if (ssl == IntPtr.Zero)
                return FAILURE;
            try
            {
                return wolfSSL_accept(ssl);
            }
            catch (Exception e)
            {
                log(1, "accept error " + e.ToString());
                return FAILURE;
            }
        }


        /// <summary>
        /// Used for a client to connect
        /// </summary>
        /// <param name="ssl">structure containing connection info</param>
        /// <returns>1 on success</returns>
        public static int connect(IntPtr ssl)
        {
            if (ssl == IntPtr.Zero)
                return FAILURE;
            try
            {
                return wolfSSL_connect(ssl);
            }
            catch (Exception e)
            {
                log(1, "connect error " + e.ToString());
                return FAILURE;
            }
        }


        /// <summary>
        /// Read message from secure connection
        /// </summary>
        /// <param name="ssl">structure containing info about connection</param>
        /// <param name="buf">object to hold incoming message</param>
        /// <param name="sz">size of available memory in buf</param>
        /// <returns>amount of data read on success</returns>
        public static int read(IntPtr ssl, StringBuilder buf, int sz)
        {
            if (ssl == IntPtr.Zero)
                return FAILURE;
            try
            {
                return wolfSSL_read(ssl, buf, sz);
            }
            catch (Exception e)
            {
                log(1, "wolfssl read error " + e.ToString());
                return FAILURE;
            }
        }


        /// <summary>
        /// Write message to secure connection
        /// </summary>
        /// <param name="ssl">structure containing connection info</param>
        /// <param name="buf">message to send</param>
        /// <param name="sz">size of the message</param>
        /// <returns>amount sent on success</returns>
        public static int write(IntPtr ssl, StringBuilder buf, int sz)
        {
            if (ssl == IntPtr.Zero)
                return FAILURE;
            try
            {
                return wolfSSL_write(ssl, buf, sz);
            }
            catch (Exception e)
            {
                log(1, "wolfssl write error " + e.ToString());
                return FAILURE;
            }
        }


        /// <summary>
        /// Free information stored in ssl struct
        /// </summary>
        /// <param name="ssl">pointer to ssl struct to free</param>
        public static void free(IntPtr ssl)
        {
            try
            {
                /* free the handle for the socket */
                IntPtr ptr = wolfSSL_GetIOReadCtx(ssl);
                if (ptr != IntPtr.Zero)
                {
                    GCHandle gch = GCHandle.FromIntPtr(ptr);
                    gch.Free();
                }
                ptr = wolfSSL_GetIOWriteCtx(ssl);
                if (ptr != IntPtr.Zero)
                {
                    GCHandle gch = GCHandle.FromIntPtr(ptr);
                    gch.Free();
                }
                wolfSSL_free(ssl);
            }
            catch (Exception e)
            {
                log(1, "wolfssl free error " + e.ToString());
            }
        }


        /// <summary>
        /// Shutdown a connection
        /// </summary>
        /// <param name="ssl">pointer to ssl struct to close connection of</param>
        /// <returns>1 on success</returns>
        public static int shutdown(IntPtr ssl)
        {
            if (ssl == IntPtr.Zero)
                return FAILURE;
            try
            {
                return wolfSSL_shutdown(ssl);
            }
            catch (Exception e)
            {
                log(1, "wolfssl shutdwon error " + e.ToString());
                return FAILURE;
            }
        }


        /// <summary>
        /// Optional, can be used to set a custom recieve function
        /// </summary>
        /// <param name="ctx">structure to set recieve function in</param>
        /// <param name="func">function to use when reading socket</param>
        public static void SetIORecv(IntPtr ctx, CallbackIORecv_delegate func)
        {
            try
            {
                wolfSSL_SetIORecv(ctx, func);
            }
            catch (Exception e)
            {
                log(1, "wolfssl setIORecv error " + e.ToString());
            }
        }


        /// <summary>
        /// Optional, can be used to set a custom send function
        /// </summary>
        /// <param name="ctx">structure to set function in</param>
        /// <param name="func">function to use when sending data</param>
        public static void SetIOSend(IntPtr ctx, CallbackIOSend_delegate func)
        {
            try
            {
                wolfSSL_SetIOSend(ctx, func);
            }
            catch (Exception e)
            {
                log(1, "wolfssl setIOSend error " + e.ToString());
            }
        }

        
        /// <summary>
        /// Create a new CTX structure
        /// </summary>
        /// <param name="method">method to use such as TLSv1.2</param>
        /// <returns>pointer to CTX structure</returns>
        public static IntPtr CTX_new(IntPtr method)
        {
            try
            {
                IntPtr ctx = wolfSSL_CTX_new(method);
                if (ctx == IntPtr.Zero)
                    return ctx;

                CallbackIORecv_delegate recv = new CallbackIORecv_delegate(wolfssl.wolfSSLCbIORecv);
                wolfSSL_SetIORecv(ctx, recv);

                CallbackIOSend_delegate send = new CallbackIOSend_delegate(wolfssl.wolfSSLCbIOSend);
                wolfSSL_SetIOSend(ctx, send);

                return ctx;
            }
            catch (Exception e)
            {
                log(1, "ctx_new error " + e.ToString());
                return IntPtr.Zero;
            }
        }


        /// <summary>
        /// Create a new CTX structure for a DTLS connection
        /// </summary>
        /// <param name="method">Method to use in connection ie DTLSv1.2</param>
        /// <returns></returns>
        public static IntPtr CTX_dtls_new(IntPtr method)
        {
            try
            {
                IntPtr ctx = wolfSSL_CTX_new(method);
                if (ctx == IntPtr.Zero)
                    return ctx;

                CallbackIORecv_delegate recv = new CallbackIORecv_delegate(wolfssl.wolfSSL_dtlsCbIORecv);
                wolfSSL_SetIORecv(ctx, recv);

                CallbackIOSend_delegate send = new CallbackIOSend_delegate(wolfssl.wolfSSL_dtlsCbIOSend);
                wolfSSL_SetIOSend(ctx, send);

                return ctx;
            }
            catch (Exception e)
            {
                log(1, "ctx_dtls_new error " + e.ToString());
                return IntPtr.Zero;
            }
        }


        /// <summary>
        /// Free information used in CTX structure
        /// </summary>
        /// <param name="ctx">structure to free</param>
        public static void CTX_free(IntPtr ctx)
        {
            try
            {
                wolfSSL_CTX_free(ctx);
            }
            catch (Exception e)
            {
                log(1, "wolfssl ctx free error " + e.ToString());
            }
        }


        /// <summary>
        /// Set identity hint to use
        /// </summary>
        /// <param name="ctx">pointer to structure of ctx to set hint in</param>
        /// <param name="hint">hint to use</param>
        /// <returns>1 on success</returns>
        public static int CTX_use_psk_identity_hint(IntPtr ctx, StringBuilder hint)
        {
            try
            {
                return wolfSSL_CTX_use_psk_identity_hint(ctx, hint);
            }
            catch (Exception e)
            {
                log(1, "wolfssl psk identity hint error " + e.ToString());
                return FAILURE;
            }
        }


        /// <summary>
        /// Set the function to use for PSK connections
        /// </summary>
        /// <param name="ctx">pointer to CTX that the function is set in</param>
        /// <param name="psk_cb">PSK function to use</param>
        public static void CTX_set_psk_server_callback(IntPtr ctx, psk_delegate psk_cb)
        {
            try
            {
                wolfSSL_CTX_set_psk_server_callback(ctx, psk_cb);
            }
            catch (Exception e)
            {
                log(1, "wolfssl psk server callback error " + e.ToString());
            }
        }


        /// <summary>
        /// Set the function to use for PSK connections on a single TLS/DTLS connection
        /// </summary>
        /// <param name="ctx">pointer to SSL that the function is set in</param>
        /// <param name="psk_cb">PSK function to use</param>
        public static void set_psk_server_callback(IntPtr ssl, psk_delegate psk_cb)
        {
            try
            {
                wolfSSL_set_psk_server_callback(ssl, psk_cb);
            }
            catch (Exception e)
            {
                log(1, "wolfssl psk server callback error " + e.ToString());
            }
        }


        /// <summary>
        /// Set Socket for TLS connection
        /// </summary>
        /// <param name="ssl">structure to set Socket in</param>
        /// <param name="fd">Socket to use</param>
        /// <returns>1 on success</returns>
        public static int set_fd(IntPtr ssl, Socket fd)
        {
            /* sanity check on inputs */
            if (ssl == IntPtr.Zero)
            {
                return FAILURE;
            }

           try
            {
                if (!fd.Equals(null))
                {
                    IntPtr ptr = GCHandle.ToIntPtr(GCHandle.Alloc(fd));
                    wolfSSL_SetIOWriteCtx(ssl, ptr); //pass along the socket for writing to
                    wolfSSL_SetIOReadCtx(ssl, ptr); //pass along the socket for reading from
                }
            }
            catch (Exception e)
            {
                log(1, "Error setting up fd!! " + e.ToString());
                return FAILURE;
            }

            return 1;
        }


        /// <summary>
        /// Get socket of a TLS connection
        /// </summary>
        /// <param name="ssl">structure to get socket from</param>
        /// <returns>Socket object used for connection</returns>
        public static Socket get_fd(IntPtr ssl)
        {
            try
            {
                IntPtr ptr = wolfSSL_GetIOReadCtx(ssl);
                if (ptr != IntPtr.Zero)
                {
                    GCHandle gch = GCHandle.FromIntPtr(ptr);
                    return (System.Net.Sockets.Socket)gch.Target;
                }
                return null;
            }
            catch (Exception e)
            {
                log(1, "wolfssl get_fd error " + e.ToString());
                return null;
            }
        }



        /// <summary>
        /// Set information needed to send and receive a DTLS connection
        /// </summary>
        /// <param name="ssl">structure to set information in</param>
        /// <param name="udp">UDP object to send and receive</param>
        /// <param name="ep">End point of connection</param>
        /// <returns>1 on success</returns>
        public static int set_dtls_fd(IntPtr ssl, UdpClient udp, IPEndPoint ep)
        {
            IntPtr ptr;
            DTLS_con con;

            /* sanity check on inputs */
            if (ssl == IntPtr.Zero)
            {
                return FAILURE;
            }

            try
            {
                if (!udp.Equals(null) && !ep.Equals(null))
                {
                    con = new DTLS_con();
                    con.udp = udp;
                    con.ep  = ep;
                    ptr = GCHandle.ToIntPtr(GCHandle.Alloc(con));
                    wolfSSL_SetIOWriteCtx(ssl, ptr); //pass along the socket for writing to
                    wolfSSL_SetIOReadCtx(ssl, ptr); //pass along the socket for reading from
                }
            }
            catch (Exception e)
            {
                log(1, "Error setting up fd!! " + e.ToString());
                return FAILURE;
            }

            return 1;
        }


        /// <summary>
        /// Get the pointer to DTLS_con class used for connection
        /// </summary>
        /// <param name="ssl">structure to get connection from</param>
        /// <returns>DTLS_con object</returns>
        public static DTLS_con get_dtls_fd(IntPtr ssl)
        {
            try
            {
                IntPtr ptr = wolfSSL_GetIOReadCtx(ssl);
                if (ptr != IntPtr.Zero)
                {
                    GCHandle gch = GCHandle.FromIntPtr(ptr);
                    return (DTLS_con)gch.Target;
                }
                return null;
            }
            catch (Exception e)
            {
                log(1, "wolfssl get_dtls_fd error " + e.ToString());
                return null;
            }
        }


        /// <summary>
        /// Get available cipher suites
        /// </summary>
        /// <param name="list">list to fill with cipher suite names</param>
        /// <param name="sz">size of list available to fill</param>
        /// <returns>1 on success</returns>
        public static int get_ciphers(StringBuilder list, int sz)
        {
            try
            {
                return wolfSSL_get_ciphers(list, sz);
            }
            catch (Exception e)
            {
                log(1, "wolfssl get_ciphers error " + e.ToString());
                return FAILURE;
            }
        }


        /// <summary>
        /// Initialize wolfSSL library
        /// </summary>
        /// <returns>1 on success</returns>
        public static int Init()
        {
            try
            {
                return wolfSSL_Init();
            }
            catch (Exception e)
            {
                log(1, "wolfssl init error " + e.ToString());
                return FAILURE;
            }
        }


        /// <summary>
        /// Clean up wolfSSL library memory
        /// </summary>
        /// <returns>1 on success</returns>
        public static int Cleanup()
        {
            try
            {
                return wolfSSL_Cleanup();
            }
            catch (Exception e)
            {
                log(1, "wolfssl cleanup error " + e.ToString());
                return FAILURE;
            }
        }


        /// <summary>
        /// Set up TLS version 1.2 method
        /// </summary>
        /// <returns>pointer to TLSv1.2 method</returns>
        public static IntPtr useTLSv1_2_server()
        {
            try
            {
                return wolfTLSv1_2_server_method();
            }
            catch (Exception e)
            {
                log(1, "wolfssl error " + e.ToString());
                return IntPtr.Zero;
            }
        }


        /// <summary>
        /// Use any TLS version
        /// </summary>
        /// <returns>pointer to method</returns>
        public static IntPtr usev23_server()
        {
            try
            {
                return wolfSSLv23_server_method();
            }
            catch (Exception e)
            {
                log(1, "wolfssl error " + e.ToString());
                return IntPtr.Zero;
            }
        }


        /// <summary>
        /// Set up TLS version 1.2 method
        /// </summary>
        /// <returns>pointer to TLSv1.2 method</returns>
        public static IntPtr useTLSv1_2_client()
        {
            try
            {
                return wolfTLSv1_2_client_method();
            }
            catch (Exception e)
            {
                log(1, "wolfssl error " + e.ToString());
                return IntPtr.Zero;
            }
        }


        /// <summary>
        /// Use any TLS version
        /// </summary>
        /// <returns>pointer to method</returns>
        public static IntPtr usev23_client()
        {
            try
            {
                return wolfSSLv23_client_method();
            }
            catch (Exception e)
            {
                log(1, "wolfssl error " + e.ToString());
                return IntPtr.Zero;
            }
        }


        /// <summary>
        /// Set up DTLS version 1.2
        /// </summary>
        /// <returns>pointer to DTLSv1.2 method</returns>
        public static IntPtr useDTLSv1_2_server()
        {
            try
            {
                return wolfDTLSv1_2_server_method();
            }
            catch (Exception e)
            {
                log(1, "wolfssl error " + e.ToString());
                return IntPtr.Zero;
            }
        }


        /// <summary>
        /// Set up DTLS version 1.2
        /// </summary>
        /// <returns>pointer to DTLSv1.2 method</returns>
        public static IntPtr useDTLSv1_2_client()
        {
            try
            {
                return wolfDTLSv1_2_client_method();
            }
            catch (Exception e)
            {
                log(1, "wolfssl error " + e.ToString());
                return IntPtr.Zero;
            }
        }


        /// <summary>
        /// Gets the current cipher suite being used in connection
        /// </summary>
        /// <param name="ssl">SSL struct to get cipher suite from</param>
        /// <returns>string containing current cipher suite</returns>
        public static string get_current_cipher(IntPtr ssl)
        {
            if (ssl == IntPtr.Zero)
                return null;
            try
            {
                IntPtr ssl_cipher;
                IntPtr ssl_cipher_ptr;
                string ssl_cipher_str;

                ssl_cipher = wolfSSL_get_current_cipher(ssl);
                ssl_cipher_ptr = wolfSSL_CIPHER_get_name(ssl_cipher);
                ssl_cipher_str = Marshal.PtrToStringAnsi(ssl_cipher_ptr);

                return ssl_cipher_str;
            }
            catch (Exception e)
            {
                log(1, "wolfssl get current cipher error " + e.ToString());
                return null;
            }
        }


        /// <summary>
        /// Set avialable cipher suites for all ssl structs created from ctx
        /// </summary>
        /// <param name="ctx">CTX structure to set</param>
        /// <param name="list">List full of ciphers suites</param>
        /// <returns>1 on success</returns>
        public static int CTX_set_cipher_list(IntPtr ctx, StringBuilder list)
        {
            try
            {
                return wolfSSL_CTX_set_cipher_list(ctx, list);
            }
            catch (Exception e)
            {
                log(1, "wolfssl ctx set cipher list error " + e.ToString());
                return FAILURE;
            }
        }


        /// <summary>
        /// Set available cipher suite in local connection
        /// </summary>
        /// <param name="ssl">Structure to set cipher suite in</param>
        /// <param name="list">List of cipher suites</param>
        /// <returns>1 on success</returns>
        public static int set_cipher_list(IntPtr ssl, StringBuilder list)
        {
            try
            {
                return wolfSSL_set_cipher_list(ssl, list);
            }
            catch (Exception e)
            {
                log(1, "wolfssl set cipher error " + e.ToString());
                return FAILURE;
            }
        }


        /// <summary>
        /// Gets the version of the connection made ie TLSv1.2
        /// </summary>
        /// <param name="ssl">SSL struct to get version of</param>
        /// <returns>string containing version</returns>
        public static string get_version(IntPtr ssl)
        {
            if (ssl == IntPtr.Zero)
                return null;

            try
            {
                IntPtr version_ptr;
                string version;

                version_ptr = wolfSSL_get_version(ssl);
                version = Marshal.PtrToStringAnsi(version_ptr);

                return version;
            }
            catch (Exception e)
            {
                log(1, "wolfssl get version error " + e.ToString());
                return null;
            }
        }


        /// <summary>
        /// Get a string containing error value and reason
        /// </summary>
        /// <param name="ssl">SSL struct that had error</param>
        /// <returns>String containing error value and reason</returns>
        public static string get_error(IntPtr ssl)
        {
            if (ssl == IntPtr.Zero)
                return null;

            try
            {
                int err;
                StringBuilder err_name;
                StringBuilder ret;

                /* wolfSSL max error length is 80 */
                ret = new StringBuilder(' ', 100);
                err = wolfSSL_get_error(ssl, 0);
                err_name = new StringBuilder(' ', 80);
                wolfSSL_ERR_error_string(err, err_name);
                ret.Append("Error " + err + " " + err_name);

                return ret.ToString();
            }
            catch (Exception e)
            {
                log(1, "wolfssl get error, error " + e.ToString());
                return null;
            }
        }


        /// <summary>
        /// Used to load in the certificate file
        /// </summary>
        /// <param name="ctx">CTX structure for TLS/SSL connections</param>
        /// <param name="fileCert">Name of the file to load including absolute path</param>
        /// <param name="type">Type of file ie PEM or DER</param>
        /// <returns>1 on success</returns>
        public static int CTX_use_certificate_file(IntPtr ctx, string fileCert, int type)
        {
            try
            {
                return wolfSSL_CTX_use_certificate_file(ctx, fileCert, type);
            }
            catch (Exception e)
            {
                log(1, "wolfssl ctx use cert file error " + e.ToString());
                return FAILURE;
            }
        }


        /// <summary>
        /// Used to load in the private key from a file 
        /// </summary>
        /// <param name="ctx">CTX structure for TLS/SSL connections </param>
        /// <param name="fileKey">Name of the file, includeing absolute directory</param>
        /// <param name="type">Type of file ie PEM or DER</param>
        /// <returns>1 on succes</returns>
        public static int CTX_use_PrivateKey_file(IntPtr ctx, string fileKey, int type)
        {
            try
            {
                return wolfSSL_CTX_use_PrivateKey_file(ctx, fileKey, type);
            }
            catch (Exception e)
            {
                log(1, "wolfssl ctx use key file error " + e.ToString());
                return FAILURE;
            }
        }


        /// <summary>
        /// Set temporary DH parameters
        /// </summary>
        /// <param name="ssl">Structure to set in</param>
        /// <param name="dhparam">file name</param>
        /// <param name="file_type">type of file ie PEM</param>
        /// <returns>1 on success</returns>
        public static int SetTmpDH_file(IntPtr ssl, StringBuilder dhparam, int file_type)
        {
            try
            {
                return wolfSSL_SetTmpDH_file(ssl, dhparam, file_type);
            }
            catch (Exception e)
            {
                log(1, "wolfssl set tmp dh file error " + e.ToString());
                return FAILURE;
            }
        }


        /// <summary>
        /// Used to set the minimum size of DH key
        /// </summary>
        /// <param name="ctx">Structure to store key size</param>
        /// <param name="minDhKey">Min key size </param>
        /// <returns>1 on success</returns>
        public static int CTX_SetMinDhKey_Sz(IntPtr ctx, short minDhKey)
        {
            try
            {
                return wolfSSL_CTX_SetMinDhKey_Sz(ctx, minDhKey);
            }
            catch (Exception e)
            {
                log(1, "wolfssl ctx set min dh key error " + e.ToString());
                return FAILURE;
            }
        }


        /// <summary>
        /// Set the function to use for logging
        /// </summary>
        /// <param name="input">Function that conforms as to loggingCb</param>
        /// <returns>1 on success</returns>
        public static int SetLogging(loggingCb input)
        {
            internal_log = input;
            return SUCCESS;
        }


        /// <summary>
        /// Log a message to set logging function
        /// </summary>
        /// <param name="lvl">Level of log message</param>
        /// <param name="msg">Message to log</param>
        public static void log(int lvl, string msg)
        {
            /* if log is not set then pring nothing */
            if (internal_log == null)
                return;
            StringBuilder ptr = new StringBuilder(msg);
            internal_log(lvl, ptr);
        }
    }
}
