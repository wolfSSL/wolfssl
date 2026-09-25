/* Program.cs
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

using System;

namespace wolfSSL.CSharp.Fips.Test
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (args.Length == 1 && args[0] == "--probe-load")
            {
                FipsModule.Initialize();   /* resolves both native libraries */
                Console.WriteLine("loaded " + FipsModule.Version);
                return 0;
            }
            if (args.Length == 2 && args[0] == "--force")
            {
                return ForcedFailureTests.Child(int.Parse(args[1]));
            }

            Console.WriteLine("wolfCrypt FIPS v5.2.1 C# wrapper tests");
            Console.WriteLine("runtime: " + System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription +
                              " (" + System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier + ")");
            Section("Module", ModuleTests.Run);
            Section("Known answers", KnownAnswerTests.Run);
            Section("Hash_DRBG", RngTests.Run);
            Section("MAC and hash", MacHashTests.Run);
            Section("AES", AesTests.Run);
            Section("RSA", RsaTests.Run);
            Section("ECC and DH", EccDhTests.Run);
            Section("KDF", KdfTests.Run);
            Section("Forced failure", ForcedFailureTests.Run);
            return T.Summary();
        }

        /* A setup step that throws outside T.Run fails its section and the
         * remaining sections still run. */
        private static void Section(string name, Action run)
        {
            try
            {
                run();
            }
            catch (Exception e)
            {
                T.Run(name + " section setup", () =>
                    throw new Exception("section aborted: " + e.GetType().Name + ": " + e.Message));
            }
        }
    }
}
