/* wolfCrypt-Test.cs
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

/* Tests for the wolfCrypt C# wrapper */

using System;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using wolfSSL.CSharp;

public class wolfCrypt_Test_CSharp
{
    private static void random_test()
    {
        int ret, i, zeroCount = 0;
        Byte[] data = new Byte[128];

        /* Random Test */
        ret = wolfcrypt.Random(data, data.Length);
        if (ret == 0) {
            /* Check for 0's */
            for (i=0; i<(int)data.Length; i++) {
                if (data[i] == 0) {
                    zeroCount++;
                }
            }
            if (zeroCount == data.Length) {
                Console.WriteLine("RNG zero check error");
            }
            else {
                Console.WriteLine("RNG Test Passed\n");
            }
        }
        else {
            Console.WriteLine("RNG Error" + wolfcrypt.GetError(ret));
        }
    }

    private static void ecc_test()
    {
        
    }

    public static void Main(string[] args)
    {
        wolfcrypt.Init();

        random_test();
        ecc_test();

        wolfcrypt.Cleanup();
    }
}
