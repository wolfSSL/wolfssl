/* ModuleTests.cs
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
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

namespace wolfSSL.CSharp.Fips.Test
{
    internal static class ModuleTests
    {
        public static void Run()
        {
            T.Section("Binding audit");

            T.Run("every libwolfssl binding targets a _fips entry point", () => {
                Type native = typeof(FipsModule).Assembly.GetType("wolfSSL.CSharp.Fips.Native")!;
                var bad = native.GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
                    .Select(m => m.GetCustomAttribute<DllImportAttribute>())
                    .Where(a => a != null && a.Value == "wolfssl" && !a.EntryPoint!.EndsWith("_fips"))
                    .Select(a => a!.EntryPoint).ToList();
                T.True(bad.Count == 0, "non-_fips bindings: " + string.Join(", ", bad));
            });

            T.Section("Module status");

            T.Run("Initialize succeeds (POST and in-core integrity passed)", () => {
                FipsModule.Initialize();
            });

            T.Run("status is 0 and mode is Normal", () => {
                T.Equal(0, FipsModule.Status, "status");
                T.Equal(FipsMode.Normal, FipsModule.Mode, "mode");
                T.True(FipsModule.IsOperational, "IsOperational");
            });

            T.Run("module version is v5.2.x", () => {
                string? v = FipsModule.Version;
                Console.WriteLine("        version: " + v);
                T.True(v != null && v.Contains("5.2"), "version string: " + v);
            });

            T.Run("computed core hash is cleared on an operational module", () => {
                T.Equal("", FipsModule.CoreHash ?? "", "CoreHash");
            });

            T.Run("on-demand integrity test passes", () => {
                T.Equal(0, FipsModule.IntegrityTest(), "IntegrityTest");
            });

            T.Section("Conditional algorithm self-tests (CASTs)");

            T.Run("RunAllCasts returns 0", () => {
                T.Equal(0, FipsModule.RunAllCasts(), "RunAllCasts");
            });

            /* Module behavior: RunCast(EccCdh) returns 0 but leaves the
             * CAST state at Processing (identical from C). The CAST result
             * is the return code, so assert that and require the state to
             * not be Failure. */
            foreach (FipsCast c in Enum.GetValues<FipsCast>()) {
                FipsCast cast = c;
                T.Run("CAST " + cast + " passes", () => {
                    T.Equal(0, FipsModule.RunCast(cast), "RunCast");
                    FipsCastState st = FipsModule.GetCastState(cast);
                    T.True(st != FipsCastState.Failure, "state " + st);
                });
            }

            T.Run("CAST enum covers all 15 v5.2.3 CASTs", () => {
                T.Equal(FipsModule.CastCount, Enum.GetValues<FipsCast>().Length, "count");
            });

            T.Section("Callbacks and key export gate");

            T.Run("failure callback registers", () => {
                FipsModule.SetFailureCallback((ok, err, hash) =>
                    Console.WriteLine("        FIPS callback: ok=" + ok + " err=" + err + " hash=" + hash));
            });

            T.Run("OS seed source registers", () => {
                FipsModule.UseOsSeed();
            });

            T.Run("private key read gate toggles", () => {
                FipsModule.SetPrivateKeyReadEnable(true);
                T.True(FipsModule.PrivateKeyReadEnabled, "enabled");
                FipsModule.SetPrivateKeyReadEnable(false);
                T.True(!FipsModule.PrivateKeyReadEnabled, "disabled");
            });

            T.Section("Native size helper");

            foreach (string s in new[] { "Rng", "Aes", "Rsa", "Ecc", "Dh", "Sha", "Sha224",
                                         "Sha256", "Sha384", "Sha512", "Sha3", "Hmac", "Cmac" }) {
                string name = s;
                T.Run("sizeof(" + name + ") available", () => {
                    Type st = typeof(FipsModule).Assembly.GetType("wolfSSL.CSharp.Fips.FipsStructType")!;
                    Type native = typeof(FipsModule).Assembly.GetType("wolfSSL.CSharp.Fips.Native")!;
                    int v = (int)Enum.Parse(st, name);
                    int sz = (int)native.GetMethod("SizeOf", BindingFlags.Static | BindingFlags.NonPublic)!
                        .Invoke(null, new object[] { v })!;
                    T.True(sz > 0, name + " size " + sz);
                });
            }
        }
    }
}
