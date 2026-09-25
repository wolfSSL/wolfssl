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
    /* Resolves the native libraries from the normal search path, or from
     * WOLFSSL_FIPS_LIB_DIR (FIPS libwolfssl plus the size helper) when set. */
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

        private static readonly object loadLock = new object();
        private static IntPtr wolfssl;
        private static string? wolfsslPath;

        /* WOLFSSL_FIPS_LIB_DIR has no fallback. The size helper always loads from
         * libwolfssl's directory, so the two cannot come from different installs. */
        private static IntPtr Resolve(string name, Assembly asm, DllImportSearchPath? path)
        {
            if (name == Native.WOLFSSL)
                return LoadWolfssl(asm, path);
            if (name == Native.SIZES) {
                LoadWolfssl(asm, path);
                string dir = Path.GetDirectoryName(wolfsslPath!)!;
                foreach (string file in Candidates(name)) {
                    string full = Path.Combine(dir, file);
                    if (File.Exists(full) && NativeLibrary.TryLoad(full, out IntPtr h))
                        return h;
                }
                throw new DllNotFoundException("size helper " + string.Join(" / ", Candidates(name)) +
                    " not found next to " + wolfsslPath + " (build it with build-native.sh)");
            }
            return IntPtr.Zero;
        }

        private static IntPtr LoadWolfssl(Assembly asm, DllImportSearchPath? path)
        {
            lock (loadLock) {
                if (wolfssl != IntPtr.Zero)
                    return wolfssl;
                string? dir = Environment.GetEnvironmentVariable("WOLFSSL_FIPS_LIB_DIR");
                IntPtr h = IntPtr.Zero;
                if (!string.IsNullOrEmpty(dir)) {
                    foreach (string file in Candidates(Native.WOLFSSL)) {
                        string full = Path.Combine(dir, file);
                        if (File.Exists(full) && NativeLibrary.TryLoad(full, out h))
                            break;
                    }
                    /* no fallback to default probing: the module must come
                     * from the directory that was asked for */
                    if (h == IntPtr.Zero)
                        throw new DllNotFoundException("WOLFSSL_FIPS_LIB_DIR is set but " +
                            string.Join(" / ", Candidates(Native.WOLFSSL)) + " could not be loaded from " + dir);
                }
                else {
                    /* NativeLibrary.Load does not re-enter this resolver */
                    h = NativeLibrary.Load(Native.WOLFSSL, asm, path);
                }
                wolfsslPath = LoadedPath(h) ?? throw new DllNotFoundException("cannot determine the file libwolfssl was loaded from");
                wolfssl = h;
                return h;
            }
        }

        /* Handle to the FIPS libwolfssl (loads it if needed). Used to look
         * up exports that are passed as function pointers. */
        internal static IntPtr WolfsslHandle() => LoadWolfssl(typeof(NativeLoader).Assembly, null);

        /* File libwolfssl was loaded from. */
        internal static string WolfsslPath
        {
            get { WolfsslHandle(); return wolfsslPath!; }
        }

        /* ---- path of a loaded library (dladdr / GetModuleFileNameW) ---- */

        [StructLayout(LayoutKind.Sequential)]
        private struct DlInfo
        {
            public IntPtr dli_fname, dli_fbase, dli_sname, dli_saddr;
        }

        private static unsafe string? LoadedPath(IntPtr lib)
        {
            /* OS lookups by function pointer (no P/Invoke outside Native.cs) */
            if (OperatingSystem.IsWindows()) {
                if (!NativeLibrary.TryLoad("kernel32.dll", out IntPtr k32) ||
                    !NativeLibrary.TryGetExport(k32, "GetModuleFileNameW", out IntPtr gmfn))
                    return null;
                char[] buf = new char[32768];
                uint n;
                fixed (char* pbuf = buf)
                    n = ((delegate* unmanaged[Stdcall]<IntPtr, char*, uint, uint>)gmfn)(lib, pbuf, (uint)buf.Length);
                return n == 0 ? null : new string(buf, 0, (int)n);
            }
            /* any libwolfssl export works as an address inside the library;
             * it is not called */
            IntPtr sym = NativeLibrary.GetExport(lib, "wolfCrypt_GetVersion_fips");
            IntPtr dladdr = IntPtr.Zero;
            foreach (string c in OperatingSystem.IsMacOS()
                         ? new[] { "/usr/lib/libSystem.B.dylib" }
                         : new[] { "libc.so.6", "libdl.so.2" }) {
                if (NativeLibrary.TryLoad(c, out IntPtr libc) && NativeLibrary.TryGetExport(libc, "dladdr", out dladdr))
                    break;
            }
            /* musl (e.g. Alpine) has neither glibc name; the process's
             * global symbol scope resolves dladdr there */
            if (dladdr == IntPtr.Zero)
                NativeLibrary.TryGetExport(NativeLibrary.GetMainProgramHandle(), "dladdr", out dladdr);
            if (dladdr == IntPtr.Zero)
                return null;
            DlInfo info;
            int ok = ((delegate* unmanaged[Cdecl]<IntPtr, DlInfo*, int>)dladdr)(sym, &info);
            if (ok == 0 || info.dli_fname == IntPtr.Zero)
                return null;
            return Path.GetFullPath(Marshal.PtrToStringUTF8(info.dli_fname)!);
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
