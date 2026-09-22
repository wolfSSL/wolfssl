/* NativeLoader.cs
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
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace wolfSSL.CSharp.Fips
{
    /* Resolves the native libraries.
     *
     * Default: the runtime probes "wolfssl" as libwolfssl.so (Linux),
     * libwolfssl.dylib (macOS) or wolfssl.dll (Windows) on the normal search
     * path, e.g. /usr/local/lib after "make install".
     *
     * Override: set WOLFSSL_FIPS_LIB_DIR to a directory that contains the
     * FIPS libwolfssl and the wolfssl_csharp_fips size helper. */
    internal static class NativeLoader
    {
        /* A module initializer is required here: the resolver must be
         * registered before the first P/Invoke into this assembly. */
#pragma warning disable CA2255
        [ModuleInitializer]
#pragma warning restore CA2255
        internal static void Init()
        {
            NativeLibrary.SetDllImportResolver(typeof(NativeLoader).Assembly, Resolve);
        }

        private static IntPtr Resolve(string name, Assembly asm, DllImportSearchPath? path)
        {
            string? dir = Environment.GetEnvironmentVariable("WOLFSSL_FIPS_LIB_DIR");
            if (string.IsNullOrEmpty(dir))
                return IntPtr.Zero; /* default probing */

            foreach (string file in Candidates(name)) {
                string full = Path.Combine(dir, file);
                if (File.Exists(full) && NativeLibrary.TryLoad(full, out IntPtr h))
                    return h;
            }
            return IntPtr.Zero;
        }

        /* Handle to the FIPS libwolfssl, resolved the same way P/Invoke
         * resolves it (override directory first, then default probing).
         * Used to look up exports that are passed as function pointers. */
        internal static IntPtr WolfsslHandle()
        {
            Assembly asm = typeof(NativeLoader).Assembly;
            IntPtr h = Resolve(Native.WOLFSSL, asm, null);
            return h != IntPtr.Zero ? h : NativeLibrary.Load(Native.WOLFSSL, asm, null);
        }

        private static string[] Candidates(string name)
        {
            if (OperatingSystem.IsWindows())
                return new[] { name + ".dll" };
            if (OperatingSystem.IsMacOS())
                return new[] { "lib" + name + ".dylib" };
            return new[] { "lib" + name + ".so" };
        }
    }
}
