/* TestRunner.cs
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
using System.Collections.Generic;

namespace wolfSSL.CSharp.Fips.Test
{
    /* Minimal dependency-free test runner, so the suite runs on target
     * devices without NuGet access. */
    internal static class T
    {
        private static int passed, failed, skipped;
        private static readonly List<string> failures = new List<string>();

        public static void Run(string name, Action test)
        {
            try {
                test();
                passed++;
                Console.WriteLine("  PASS  " + name);
            }
            catch (SkipException e) {
                skipped++;
                Console.WriteLine("  SKIP  " + name + ": " + e.Message);
            }
            catch (Exception e) {
                failed++;
                failures.Add(name);
                Console.WriteLine("  FAIL  " + name + ": " + e.GetType().Name + ": " + e.Message);
            }
        }

        public static void Section(string name) => Console.WriteLine("\n[" + name + "]");

        public static int Summary()
        {
            Console.WriteLine("\n" + passed + " passed, " + failed + " failed, " + skipped + " skipped");
            foreach (var f in failures)
                Console.WriteLine("  failed: " + f);
            return failed == 0 ? 0 : 1;
        }

        public static void True(bool cond, string msg)
        {
            if (!cond) throw new Exception("assert: " + msg);
        }

        public static void Equal<TV>(TV expected, TV actual, string msg)
        {
            if (!EqualityComparer<TV>.Default.Equals(expected, actual))
                throw new Exception("assert " + msg + ": expected " + expected + ", got " + actual);
        }

        public static void Bytes(byte[] expected, byte[] actual, string msg)
        {
            if (Convert.ToHexString(expected) != Convert.ToHexString(actual))
                throw new Exception("assert " + msg + ": expected " + Convert.ToHexString(expected)
                    + ", got " + Convert.ToHexString(actual));
        }

        public static void Throws(int expectedCode, Action a, string msg)
        {
            try { a(); }
            catch (WolfCryptFipsException e) {
                if (e.Code != expectedCode)
                    throw new Exception("assert " + msg + ": expected " + FipsError.Name(expectedCode)
                        + ", got " + FipsError.Name(e.Code));
                return;
            }
            throw new Exception("assert " + msg + ": expected " + FipsError.Name(expectedCode) + ", no error");
        }

        public static byte[] Hex(string s) => Convert.FromHexString(s.Replace(" ", ""));

        public static void Skip(string why) => throw new SkipException(why);
    }

    internal class SkipException : Exception
    {
        public SkipException(string m) : base(m) { }
    }
}
