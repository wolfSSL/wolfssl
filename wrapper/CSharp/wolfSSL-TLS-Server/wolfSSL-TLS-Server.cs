/* wolfSSL-TLS-Server.cs
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

using System;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using System.Net;
using System.Net.Sockets;
using wolfSSL.CSharp;

public class wolfSSL_TLS_CSHarp
{
    /// <summary>
    /// Example of a logging function
    /// </summary>
    /// <param name="lvl">level of log</param>
    /// <param name="msg">message to log</param>
    public static void standard_log(int lvl, StringBuilder msg)
    {
        Console.WriteLine(msg);
    }


    private static void clean(IntPtr ssl, IntPtr ctx)
    {
        wolfssl.free(ssl);
        wolfssl.CTX_free(ctx);
        wolfssl.Cleanup();
    }

    /// <summary>
    /// Checks if the SNI option was enabled via command line.
    /// Must be enabled with ./configure --enable-sni when configuring
    /// wolfSSL.
    /// <param name="args">Parameters passed via command line</param>
    /// </summary>
    private static bool haveSNI(string[] args)
    {
        bool sniON = false;
        for (int i = 0; i < args.Length; i++) {
            if (args[i] == "-S") {
                sniON = true;
                break;
            }
        }
        Console.WriteLine("SNI IS: " + sniON);
        return sniON;
    }

    /// <summary>
    /// Example of a SNI function call back
    /// </summary>
    /// <param name="ssl">pointer to ssl structure</param>
    /// <param name="ret">alert code</param>
    /// <param name="exArg">context arg, can be set with the function wolfssl.CTX_set_servername_arg</param>
    /// <returns></returns>
    public static int my_sni_server_cb(IntPtr ssl, IntPtr ret, IntPtr exArg) {
        /* Trivial callback just for testing */
        Console.WriteLine("my sni server callback");

        return 0;
    }

    public static void Main(string[] args)
    {
        IntPtr ctx;
        IntPtr ssl;
        Socket fd;
        IntPtr arg_sni;

        /* These paths should be changed for use */
        string fileCert = wolfssl.setPath("server-cert.pem");
        string fileKey = wolfssl.setPath("server-key.pem");
        StringBuilder dhparam = new StringBuilder(wolfssl.setPath("dh2048.pem"));

        if (fileCert == "" || fileKey == "" || dhparam.Length == 0) {
            Console.WriteLine("Platform not supported.");
            return;
        }

        StringBuilder buff = new StringBuilder(1024);
        StringBuilder reply = new StringBuilder("Hello, this is the wolfSSL C# wrapper");

        //example of function used for setting logging
        wolfssl.SetLogging(standard_log);

        wolfssl.Init();

        Console.WriteLine("Calling ctx Init from wolfSSL");
        ctx = wolfssl.CTX_new(wolfssl.usev23_server());
        if (ctx == IntPtr.Zero)
        {
            Console.WriteLine("Error in creating ctx structure");
            return;
        }
        Console.WriteLine("Finished init of ctx .... now load in cert and key");

        if (!File.Exists(fileCert) || !File.Exists(fileKey))
        {
            Console.WriteLine("Could not find cert or key file");
            wolfssl.CTX_free(ctx);
            return;
        }

        if (!File.Exists(dhparam.ToString())) {
            Console.WriteLine("Could not find dh file");
            wolfssl.CTX_free(ctx);
            return;
        }

        if (wolfssl.CTX_use_certificate_file(ctx, fileCert, wolfssl.SSL_FILETYPE_PEM) != wolfssl.SUCCESS)
        {
            Console.WriteLine("Error in setting cert file");
            wolfssl.CTX_free(ctx);
            return;
        }

        if (wolfssl.CTX_use_PrivateKey_file(ctx, fileKey, wolfssl.SSL_FILETYPE_PEM) != wolfssl.SUCCESS)
        {
            Console.WriteLine("Error in setting key file");
            wolfssl.CTX_free(ctx);
            return;
        }

        StringBuilder ciphers = new StringBuilder(new String(' ', 4096));
        wolfssl.get_ciphers(ciphers, 4096);
        Console.WriteLine("Ciphers : " + ciphers.ToString());

        short minDhKey = 128;
        wolfssl.CTX_SetMinDhKey_Sz(ctx, minDhKey);

        /* set up TCP socket */
        IPAddress ip = IPAddress.Parse("0.0.0.0"); /* bind to any */
        TcpListener tcp = new TcpListener(ip, 11111);
        tcp.Start();

        Console.WriteLine("Started TCP and waiting for a connection");
        fd = tcp.AcceptSocket();

        ssl = wolfssl.new_ssl(ctx);
        if (ssl == IntPtr.Zero)
        {
            Console.WriteLine("Error in creating ssl object");
            wolfssl.CTX_free(ctx);
            return;
        }

        if (haveSNI(args)) 
        {
           // Allocating memory and setting SNI arg
           int test_value = 32;
           arg_sni = Marshal.AllocHGlobal(sizeof(int));
           Marshal.WriteInt32(arg_sni, test_value);
           if (wolfssl.CTX_set_servername_arg(ctx, arg_sni) == wolfssl.FAILURE) {
               Console.WriteLine("wolfssl.CTX_set_servername_arg failed");
               wolfssl.CTX_free(ctx);
               return;
           }

           // Setting SNI delegate
           wolfssl.sni_delegate sni_cb  = new wolfssl.sni_delegate(my_sni_server_cb);
           wolfssl.CTX_set_servername_callback(ctx, sni_cb);
        }

        Console.WriteLine("Connection made wolfSSL_accept ");
        if (wolfssl.set_fd(ssl, fd) != wolfssl.SUCCESS)
        {
            /* get and print out the error */
            Console.WriteLine(wolfssl.get_error(ssl));
            tcp.Stop();
            clean(ssl, ctx);
            return;
        }

        if (wolfssl.SetTmpDH_file(ssl, dhparam, wolfssl.SSL_FILETYPE_PEM) != wolfssl.SUCCESS)
        {
            Console.WriteLine("Error in setting dh2048Pem");
            Console.WriteLine(wolfssl.get_error(ssl));
            tcp.Stop();
            clean(ssl, ctx);
            return;
        }

        if (wolfssl.accept(ssl) != wolfssl.SUCCESS)
        {
            /* get and print out the error */
            Console.WriteLine(wolfssl.get_error(ssl));
            tcp.Stop();
            clean(ssl, ctx);
            return;
        }

        /* get and print sni used by the client */
        if (haveSNI(args)) {
            IntPtr data = IntPtr.Zero;

            ushort size = wolfssl.SNI_GetRequest(ssl, 0, ref data);
            string dataStr = Marshal.PtrToStringAnsi(data);
            Console.WriteLine("(SNI_GetRequest) Size of SNI used by client: " + size);
            Console.WriteLine("(SNI_GetRequest) SNI used by client: " + dataStr);
        }

        /* print out results of TLS/SSL accept */
        Console.WriteLine("SSL version is " + wolfssl.get_version(ssl));
        Console.WriteLine("SSL cipher suite is " + wolfssl.get_current_cipher(ssl));

        /* read and print out the message then reply */
        if (wolfssl.read(ssl, buff, 1024) < 0)
        {
            Console.WriteLine("Error in read");
            tcp.Stop();
            clean(ssl, ctx);
            return;
        }
        Console.WriteLine(buff);

        /* get and print sni from a sample buffer, can be used by using the raw client hello */
        if (haveSNI(args)) {
            IntPtr result = Marshal.AllocHGlobal(32);
            IntPtr inOutSz = Marshal.AllocHGlobal(sizeof(int));
            Marshal.WriteInt32(inOutSz, 32);
            byte [] buffer = { /* www.paypal.com */
                0x16, 0x03, 0x03, 0x00, 0x64, 0x01, 0x00, 0x00, 0x60, 0x03, 0x03, 0x5c,
                0xc4, 0xb3, 0x8c, 0x87, 0xef, 0xa4, 0x09, 0xe0, 0x02, 0xab, 0x86, 0xca,
                0x76, 0xf0, 0x9e, 0x01, 0x65, 0xf6, 0xa6, 0x06, 0x13, 0x1d, 0x0f, 0xa5,
                0x79, 0xb0, 0xd4, 0x77, 0x22, 0xeb, 0x1a, 0x00, 0x00, 0x16, 0x00, 0x6b,
                0x00, 0x67, 0x00, 0x39, 0x00, 0x33, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35,
                0x00, 0x2f, 0x00, 0x05, 0x00, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x21,
                0x00, 0x00, 0x00, 0x13, 0x00, 0x11, 0x00, 0x00, 0x0e, 0x77, 0x77, 0x77,
                0x2e, 0x70, 0x61, 0x79, 0x70, 0x61, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x00,
                0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x01, 0x02, 0x01
            };

            int ret = wolfssl.SNI_GetFromBuffer(buffer, 1024, 0, result, inOutSz); 
            
            if (ret != wolfssl.SUCCESS) {
                Console.WriteLine("Error on reading SNI from buffer, ret value = " + ret);
                tcp.Stop();
                clean(ssl, ctx);
                return;
            }

            string resultStr = Marshal.PtrToStringAnsi(result);
            Console.WriteLine("(SNI_GetFromBuffer) SNI used by client: " + resultStr);

        }

        if (wolfssl.write(ssl, reply, reply.Length) != reply.Length)
        {
            Console.WriteLine("Error in write");
            tcp.Stop();
            clean(ssl, ctx);
            return;
        }

        wolfssl.shutdown(ssl);
        fd.Close();
        tcp.Stop();

        clean(ssl, ctx);
    }
}
