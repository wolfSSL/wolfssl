/* wolfSSL-TLS-Client.cs
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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


// Optionally set explicit cipher, see CIPHER_SUITE and wolfssl.CTX_set_cipher_list()
#define USE_SPECIFIED_CIPHER

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using wolfSSL;
using wolfSSL.CSharp;

public class wolfSSL_TLS_Client
{
    // Sample listening server:
    // See https://github.com/wolfSSL/wolfssl/tree/master/examples/server
    //
    // Examples disable client cert check with `-d`:
    //   ./examples/server/server -d -p 11111 -c ./certs/server-cert.pem -k ./certs/server-key.pem
    //   ./examples/server/server -d -p 12345
    //
    // Ensure the -p [port] for client matches SERVER_PORT value here:
    //
    public static string SERVER_NAME = "192.168.142.146"; /* or IP address: "192.168.1.73 */
    public static int SERVER_PORT = 11111;
    private static int byte_ct = 0; /* How many byte sent / received  */

    // public static string CIPHER_SUITE = "DHE-RSA-AES256-GCM-SHA384"; /* TLS 1.2 TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 */
    public static string CIPHER_SUITE = "TLS13-AES256-GCM-SHA384";

    public static void standard_log(int lvl, string msg) {
        Console.WriteLine(msg);
    }

    /// <summary>
    /// Show error code and level for either last transmit or receive history parameter
    /// </summary>
    /// <param name="h"></param>
    /// <param name="m"></param>
    private static void show_alert_history_code(WOLFSSL_ALERT h, string m)
    {
        /* VS initializes .code and .level to zero; wolfSSL sets to -1 until there's a valid value. */
        if ((h.code > 0) || (h.level > 0)) {
            Console.WriteLine(m + " code:  " + h.code.ToString());
            Console.WriteLine(m + " level: " + h.level.ToString());
        }
    }

    /// <summary>
    /// Show alert history for both transmit and receive
    /// </summary>
    /// <param name="ssl"></param>
    private static void show_alert_history(IntPtr ssl)
    {
        WOLFSSL_ALERT_HISTORY myHistory = new WOLFSSL_ALERT_HISTORY();
        int ret = 0;
        ret = wolfssl.get_alert_history(ssl, ref myHistory);
        if (ret == wolfssl.SUCCESS) {
            show_alert_history_code(myHistory.last_tx, "myHistory last_tx");
            show_alert_history_code(myHistory.last_rx, "myHistory last_rx");
        }
        else {
            Console.WriteLine("Failed: call to get_alert_history failed with error " + ret.ToString());
        }
    }

    /// <summary>
    /// Cleanup both ssl and ctx, releasing memory as needed.
    /// </summary>
    /// <param name="ssl"></param>
    /// <param name="ctx"></param>
    private static void clean(IntPtr ssl, IntPtr ctx)
    {
        wolfssl.free(ssl);
        wolfssl.CTX_free(ctx);
        wolfssl.Cleanup();
    }

    /// <summary>
    /// Verification callback
    /// </summary>
    /// <param name="preverify">1=Verify Okay, 0=Failure</param>
    /// <param name="x509_ctx">Certificate in WOLFSSL_X509_STORE_CTX format</param>
    private static int myVerify(int preverify, IntPtr x509_ctx)
    {
        int verify = preverify;

        /* example for overriding an error code */
        /* X509_STORE_CTX_get_error API can be enabled with
         * OPENSSL_EXTRA_X509_SMALL or WOLFSSL_EXTRA */
        int error = wolfssl.X509_STORE_CTX_get_error(x509_ctx);
        if (error == wolfcrypt.ASN_BEFORE_DATE_E) {
            verify = 1; /* override error */
        }

        /* Can optionally override failures by returning non-zero value */
        return verify;
    }

    /// <summary>
    /// Checks if the SNI option was enabled via command line.
    /// Must be enabled with ./configure --enable-sni when configuring
    /// wolfSSL.
    /// <param name="args">Parameters passed via command line</param>
    /// </summary>
    private static int haveSNI(string[] args)
    {
        for (int i = 0; i < args.Length; i++) {
            if (args[i] == "-S") {
                Console.WriteLine("SNI IS ON");
                return i+1;
            }
        }
        Console.WriteLine("SNI IS OFF");
        return -1;
    }

    /// <summary>
    /// Checks environment, attempts to manually load wolfssl.dll if not found in current directory.
    /// </summary>
    /// <returns>True if wolfssl.dll was found</returns>
    private static bool CheckEnvironment() {
        bool ret = false;
        /* Ensure the DLL is loaded properly */
#if WindowsCE
        string exePath = System.Reflection.Assembly.GetExecutingAssembly().GetName().CodeBase;
        Console.WriteLine("Executable Path:   " + exePath);
#else
        Console.WriteLine("Current Directory: " + Environment.CurrentDirectory);
#endif
        if (File.Exists("wolfssl.dll")) {
            string fullPath = Path.GetFullPath("wolfssl.dll");
            Console.WriteLine("Found wolfssl.dll " + fullPath);
            ret = true;
        }
        else {
            /* Consider copying to working directory, or adding to path */
            Console.WriteLine("ERROR: Could not find wolfssl.dll; trying explicit load...");
            ret = wolfssl.LoadDLL(true); /* look in default directory, otherwise pass explicit path */
        }
        wolfssl.SetVerbosity(true);
        wolfcrypt.SelfCheck();
        return ret;
    }

    public static void Main(string[] args)
    {
        IntPtr ctx;
        IntPtr ssl;
        Socket tcp;
        IntPtr sniHostName;

        /* Optional check of environment */
        CheckEnvironment();

        /* These paths should be changed for use */
        string caCert = wolfssl.setPath("ca-cert.pem");
        string clientCert = wolfssl.setPath("client-cert.pem");
        string clientKey = wolfssl.setPath("client-key.pem");
        string dhparam = new StringBuilder(wolfssl.setPath("dh2048.pem")).ToString();

        if (caCert == "" || dhparam.Length == 0) {
            Console.WriteLine("Platform not supported.");
            return;
        }

        StringBuilder buff = new StringBuilder(1024);
        StringBuilder tx_msg = new StringBuilder("Hello, this is the wolfSSL C# wrapper");

        /* example of function used for setting logging */
        wolfssl.SetLogging(standard_log);

        /* optionally clear logging callback */
        /* wolfssl.ClearLogging(); */

        wolfssl.Init();

        Console.WriteLine("Calling ctx Init from wolfSSL");

        /* Use any version of TLS */
        // ctx = wolfssl.CTX_new(wolfssl.usev23_client());

        /* Only TLS 1.3 */
        ctx = wolfssl.CTX_new(wolfssl.useTLSv1_3_client());
        if (ctx == IntPtr.Zero)
        {
            Console.WriteLine("Error in creating ctx structure");
            return;
        }

        foreach (TLSVersion v in wolfssl.TLSVersions) {
            int result = wolfssl.CTX_SetMinVersion(ctx, v.Value);
            Console.Write("MinVersion set to " + v.Value.ToString() + " " + v.Name );
            if (result == wolfssl.SUCCESS) {
                Console.WriteLine(" OK");
            }
            else {
                Console.WriteLine(" Not supported for this build configuration");
            }
        }

        long opts = wolfssl.CTX_get_options(ctx);

        Console.WriteLine("Finished init of ctx .... now load in CA");

        if (!File.Exists(caCert))
        {
            Console.WriteLine("Could not find CA cert file");
            wolfssl.CTX_free(ctx);
            return;
        }

        if (!File.Exists(dhparam.ToString())) {
            Console.WriteLine("Could not find dh file");
            wolfssl.CTX_free(ctx);
            return;
        }

        if (wolfssl.CTX_use_certificate_file(ctx, clientCert, wolfssl.SSL_FILETYPE_PEM) != wolfssl.SUCCESS) {
            Console.WriteLine("Error loading Client cert: " + clientCert);
            wolfssl.CTX_free(ctx);
            return;
        }

        if (wolfssl.CTX_use_PrivateKey_file(ctx, clientKey, wolfssl.SSL_FILETYPE_PEM) != wolfssl.SUCCESS) {
            Console.WriteLine("Error loading Client key: " + clientKey);
            wolfssl.CTX_free(ctx);
            return;
        }


        if (wolfssl.CTX_load_verify_locations(ctx, caCert, null)
            != wolfssl.SUCCESS)
        {
            Console.WriteLine("Error loading CA cert");
            wolfssl.CTX_free(ctx);
            return;
        }

        int sniArg = haveSNI(args);
        if (sniArg >= 0)
        {
            string sniHostNameString = args[sniArg].Trim();
            sniHostName = wolfssl.StringToAnsiPtr(sniHostNameString);

            ushort size = (ushort)sniHostNameString.Length;

           if (wolfssl.CTX_UseSNI(ctx, (byte)wolfssl.WOLFSSL_SNI_HOST_NAME, sniHostName, size) != wolfssl.SUCCESS)
           {
               Console.WriteLine("UseSNI failed");
               wolfssl.CTX_free(ctx);
               return;
           }
        }

        StringBuilder ciphers = new StringBuilder(new String(' ', 4096));
        wolfssl.get_ciphers(ciphers, 4096);
        Console.WriteLine("Ciphers:\r\n" + ciphers.ToString().Replace(":", "\r\n"));

        /* Uncomment Section to enable specific cipher suite */
#if USE_SPECIFIED_CIPHER
        ciphers = new StringBuilder(CIPHER_SUITE);
        if (wolfssl.CTX_set_cipher_list(ctx, ciphers.ToString()) != wolfssl.SUCCESS)
        {
            Console.WriteLine("ERROR CTX_set_cipher_list()");
            wolfssl.CTX_free(ctx);
            return;
        }
#endif

        short minDhKey = 128;
        wolfssl.CTX_SetMinDhKey_Sz(ctx, minDhKey);

        /* Setup Verify Callback */
        if (wolfssl.CTX_set_verify(ctx, wolfssl.SSL_VERIFY_PEER, myVerify)
            != wolfssl.SUCCESS)
        {
            Console.WriteLine("Error setting verify callback!");
        }


        /* set up TCP socket */
        tcp = new Socket(AddressFamily.InterNetwork, SocketType.Stream,
                              ProtocolType.Tcp);
        try
        {
#if WindowsCE || PocketPC
            IPAddress[] addresses = Dns.GetHostEntry(SERVER_NAME).AddressList;
            foreach (IPAddress addr in addresses)
            {
                if (addr.AddressFamily == AddressFamily.InterNetwork)
                {
                    tcp.Connect(new IPEndPoint(addr, SERVER_PORT));
                    break; /* use only one connection */
                }
            }
#else
            tcp.Connect(SERVER_NAME, SERVER_PORT);
#endif
        }
        catch (Exception e)
        {
            Console.WriteLine("tcp.Connect() error " + e.ToString());
            wolfssl.CTX_free(ctx);
            return;
        }
        if (!tcp.Connected)
        {
            Console.WriteLine("tcp.Connect() failed!");
            tcp.Close();
            wolfssl.CTX_free(ctx);
            return;
        }

        Console.WriteLine("Connected TCP");
        ssl = wolfssl.new_ssl(ctx);
        if (ssl == IntPtr.Zero)
        {
            Console.WriteLine("Error in creating ssl object");
            wolfssl.CTX_free(ctx);
            return;
        }

        Console.WriteLine("Created new ssl object");
        if (wolfssl.set_fd(ssl, tcp) != wolfssl.SUCCESS)
        {
            /* get and print out the error */
            Console.WriteLine(wolfssl.get_error(ssl));
            tcp.Close();
            clean(ssl, ctx);
            return;
        }

        wolfssl.SetTmpDH_file(ssl, dhparam, wolfssl.SSL_FILETYPE_PEM);
        opts = wolfssl.CTX_get_options(ctx);
        opts = wolfssl.CTX_set_options(ctx, 1);
        opts = wolfssl.CTX_clear_options(ctx, 1);
        if (wolfssl.connect(ssl) != wolfssl.SUCCESS)
        {
            Console.WriteLine("Connection fsailed wolfssl.connect(ssl)");

            /* get and print out the error */
            Console.WriteLine(wolfssl.get_error(ssl));
            show_alert_history(ssl);

            tcp.Close();
            clean(ssl, ctx);
            return;
        }

        /* print out results of TLS/SSL accept */
        Console.WriteLine("SSL version is " + wolfssl.get_version(ssl));
        Console.WriteLine("SSL cipher suite is " + wolfssl.get_current_cipher(ssl));

        Console.WriteLine("Writing message to server: " + tx_msg);
        byte_ct = wolfssl.write(ssl, tx_msg, tx_msg.Length);
        if (byte_ct != tx_msg.Length)
        {
            Console.WriteLine("Error in write");
            Console.WriteLine("Bytes sent: " + byte_ct.ToString());
            tcp.Close();
            clean(ssl, ctx);
            return;
        }
        Console.WriteLine("Sent " + byte_ct.ToString() + " bytes to server!");

        Console.WriteLine("Reading server response...");
        byte_ct = wolfssl.read(ssl, buff, 1023);
        /* read and print out the message then reply */
        if (byte_ct < 0)
        {
            Console.WriteLine("Error in read");
            tcp.Close();
            clean(ssl, ctx);
            return;
        }
        Console.WriteLine("Read " + byte_ct.ToString() + " byte reply from server!");
        Console.WriteLine(buff);

        /* Optional code & level history */
        show_alert_history(ssl);

        wolfssl.shutdown(ssl);
        tcp.Close();
        clean(ssl, ctx);
    }
}
