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
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Threading;
using System.Security.Cryptography;

namespace wolfSSL.CSharp.Fips.Test
{
    internal static class ModuleTests
    {
        public static void Run()
        {
            T.Section("Binding audit");

            T.Run("every libwolfssl binding in the assembly targets a _fips entry point", () =>
            {
                var all = typeof(FipsModule).Assembly.GetTypes()
                    .SelectMany(t => t.GetMethods(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public |
                                                  BindingFlags.DeclaredOnly))
                    .Select(m => (m, a: m.GetCustomAttribute<DllImportAttribute>()))
                    .Where(x => x.a != null).ToList();
                var bad = all.Where(x => x.a!.Value != "wolfssl_csharp_fips" &&
                                         !(x.a.EntryPoint ?? x.m.Name).EndsWith("_fips"))
                             .Select(x => x.m.DeclaringType!.Name + "." + x.m.Name).ToList();
                T.True(all.Count > 100, "found " + all.Count + " P/Invoke methods");
                T.True(all.All(x => x.m.DeclaringType!.Name == "Native"), "P/Invoke outside Native");
                T.True(bad.Count == 0, "non-_fips bindings: " + string.Join(", ", bad));
            });

            T.Section("Module status");

            T.Run("Initialize succeeds (POST and in-core integrity passed)", () =>
            {
                FipsModule.Initialize();
            });

            T.Run("status is 0 and mode is Normal", () =>
            {
                T.Equal(0, FipsModule.Status, "status");
                T.Equal(FipsMode.Normal, FipsModule.Mode, "mode");
                T.True(FipsModule.IsOperational, "IsOperational");
            });

            T.Run("module version is v5.2.x", () =>
            {
                string? v = FipsModule.Version;
                Console.WriteLine("        version: " + v);
                T.True(v != null && v.Contains("5.2"), "version string: " + v);
            });

            T.Run("computed core hash is cleared on an operational module", () =>
            {
                T.Equal("", FipsModule.CoreHash ?? "", "CoreHash");
            });

            /* the native call always returns 0; IntegrityTest returns the
             * status afterwards, so this can fail */
            T.Run("on-demand integrity test passes", () =>
            {
                T.Equal(0, FipsModule.IntegrityTest(), "IntegrityTest (module status)");
                T.Equal(FipsMode.Normal, FipsModule.Mode, "mode");
                T.True(FipsModule.IsOperational, "operational");
            });

            T.Section("Conditional algorithm self-tests (CASTs)");

            T.Run("RunAllCasts returns 0", () =>
            {
                T.Equal(0, FipsModule.RunAllCasts(), "RunAllCasts");
            });

            /* Module behavior: RunCast(EccCdh) returns 0 but leaves the
             * CAST state at Processing (identical from C). The CAST result
             * is the return code, so assert that and require the state to
             * not be Failure. */
            foreach (FipsCast c in Enum.GetValues<FipsCast>())
            {
                FipsCast cast = c;
                T.Run("CAST " + cast + " passes", () =>
                {
                    T.Equal(0, FipsModule.RunCast(cast), "RunCast");
                    FipsCastState st = FipsModule.GetCastState(cast);
                    T.True(st != FipsCastState.Failure, "state " + st);
                });
            }

            /* wc_RunCast_fips writes its state array before checking the
             * id, so these must never reach the module */
            T.Run("RunCast and GetCastState refuse out-of-range CAST ids", () =>
            {
                foreach (int id in new[] { -1, FipsModule.CastCount, int.MinValue, int.MaxValue })
                {
                    bool threw = false, threwState = false;
                    try { FipsModule.RunCast((FipsCast)id); } catch (ArgumentOutOfRangeException) { threw = true; }
                    try { FipsModule.GetCastState((FipsCast)id); } catch (ArgumentOutOfRangeException) { threwState = true; }
                    T.True(threw, "RunCast: CAST id " + id + " accepted");
                    T.True(threwState, "GetCastState: CAST id " + id + " accepted");
                }
                T.True(FipsModule.IsOperational, "operational");
            });

            /* Asks the module: the last CAST id is valid and the next is out
             * of range (wc_GetCastStatus_fips returns -1). */
            T.Run("CAST enum matches the module's CAST count", () =>
            {
                T.True(Native.wc_GetCastStatus_fips(FipsModule.CastCount - 1) >= 0, "last CAST id rejected");
                T.Equal(-1, Native.wc_GetCastStatus_fips(FipsModule.CastCount), "id past the end");
                T.Equal(FipsModule.CastCount, Enum.GetValues<FipsCast>().Length, "enum size");
            });

            T.Section("Callbacks and key export gate");

            T.Run("failure callback registers", () =>
            {
                FipsModule.SetFailureCallback((ok, err, hash) =>
                    Console.WriteLine("        FIPS callback: ok=" + ok + " err=" + err + " hash=" + hash));
            });

            T.Run("OS seed source registers", () =>
            {
                FipsModule.UseOsSeed();
            });

            T.Run("Initialize keeps a custom seed source registered earlier", () =>
            {
                int calls = 0;
                FipsModule.SetSeedCallback((os, seed, sz) =>
                {
                    unsafe { RandomNumberGenerator.Fill(new Span<byte>((void*)seed, (int)sz)); }
                    Interlocked.Increment(ref calls);
                    return 0;
                });
                FipsModule.Initialize();   /* e.g. a second component starting up */
                using (var r = new FipsRng())
                {
                    r.Generate(16);
                }

                T.True(calls > 0, "Initialize replaced the custom seed source");
                FipsModule.UseOsSeed();
                int before = calls;
                FipsModule.Initialize();
                using (var r = new FipsRng())
                {
                    r.Generate(16);
                }

                T.Equal(before, calls, "custom callback still registered after UseOsSeed");
            });

            T.Run("custom seed callback is used, then the OS source restored", () =>
            {
                int calls = 0;
                FipsModule.SetSeedCallback((os, seed, sz) =>
                {
                    unsafe { RandomNumberGenerator.Fill(new Span<byte>((void*)seed, (int)sz)); }
                    Interlocked.Increment(ref calls);
                    return 0;
                });
                using (var r = new FipsRng())
                {
                    r.Generate(16);
                }

                T.True(calls > 0, "seed callback not called");
                FipsModule.UseOsSeed();
                int before = calls;
                using (var r = new FipsRng())
                {
                    r.Generate(16);
                }

                T.Equal(before, calls, "custom callback still registered");
            });

            /* Objects used only for their final call must stay alive while
             * the module runs (SafeHandle); a GC with finalization runs in
             * parallel to provoke early collection. */
            T.Run("native state survives GC during calls on last-use objects", () =>
            {
                using var stop = new CancellationTokenSource();
                var gc = Task.Run(() =>
                {
                    while (!stop.IsCancellationRequested)
                    {
                        GC.Collect();
                        GC.WaitForPendingFinalizers();
                    }
                });
                try
                {
                    byte[] key = new byte[16], iv = new byte[16], msg = new byte[4096];
                    byte[] expected = FipsAes.CreateCbc(key, iv, true).Transform(msg);
                    for (int i = 0; i < 2000; i++)
                    {
                        T.Equal(32, new FipsRng().Generate(32).Length, "rng");
                        T.Bytes(expected, FipsAes.CreateCbc(key, iv, true).Transform(msg), "cbc");
                        T.Equal(32, FipsHash.Compute(FipsHashType.Sha256, msg).Length, "sha");
                    }
                }
                finally
                {
                    stop.Cancel();
                    gc.Wait();
                }
            });

            T.Run("seed callback: null refused, replacement and a throwing callback are safe", () =>
            {
                bool threw = false;
                try { FipsModule.SetSeedCallback(null!); } catch (ArgumentNullException) { threw = true; }
                T.True(threw, "null accepted");
                int a = 0, b = 0;
                FipsModule.SetSeedCallback((os, seed, sz) => { Interlocked.Increment(ref a); unsafe { RandomNumberGenerator.Fill(new Span<byte>((void*)seed, (int)sz)); } return 0; });
                FipsModule.SetSeedCallback((os, seed, sz) => { Interlocked.Increment(ref b); unsafe { RandomNumberGenerator.Fill(new Span<byte>((void*)seed, (int)sz)); } return 0; });
                GC.Collect(); GC.WaitForPendingFinalizers();
                using (var r = new FipsRng())
                {
                    r.Generate(8);
                }

                T.True(b > 0 && a == 0, "replacement callback not used");
                FipsModule.SetSeedCallback((os, seed, sz) => throw new InvalidOperationException("boom"));
                bool failed = false;
                try { new FipsRng().Dispose(); } catch (WolfCryptFipsException) { failed = true; }
                T.True(failed, "DRBG instantiated from a throwing seed callback");
                FipsModule.UseOsSeed();
                using (var r = new FipsRng())
                {
                    r.Generate(8);
                }
            });

            T.Run("private key read gate: one disable closes a nested gate", () =>
            {
                /* raise the module's per-thread counter directly */
                T.Equal(0, Native.wolfCrypt_SetPrivateKeyReadEnable_fips(1, 0), "native enable");
                T.Equal(0, Native.wolfCrypt_SetPrivateKeyReadEnable_fips(1, 0), "native enable");
                T.Equal(0, Native.wolfCrypt_SetPrivateKeyReadEnable_fips(1, 0), "native enable");
                T.True(Native.wolfCrypt_GetPrivateKeyReadEnable_fips(0) > 1, "counter did not nest");
                FipsModule.SetPrivateKeyReadEnable(false);
                T.True(!FipsModule.PrivateKeyReadEnabled, "gate still open");
            });

            T.Run("WOLFSSL_FIPS_LIB_DIR pointing at a directory without the libraries fails loudly", () =>
            {
                string empty = Path.Combine(Path.GetTempPath(), "wolfcrypt-fips-empty-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(empty);
                try
                {
                    var psi = new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!)
                    {
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false
                    };
                    if (Path.GetFileNameWithoutExtension(Environment.ProcessPath!) == "dotnet")
                    {
                        psi.ArgumentList.Add(typeof(ModuleTests).Assembly.Location);
                    }

                    psi.ArgumentList.Add("--probe-load");
                    psi.Environment["WOLFSSL_FIPS_LIB_DIR"] = empty;
                    using var p = System.Diagnostics.Process.Start(psi)!;
                    var o = p.StandardOutput.ReadToEndAsync(); var e = p.StandardError.ReadToEndAsync();
                    if (!p.WaitForExit(120_000))
                    {
                        p.Kill(entireProcessTree: true);
                        p.WaitForExit();
                        throw new Exception("probe-load child timed out");
                    }
                    string all = o.Result + e.Result;
                    T.True(p.ExitCode != 0 && all.Contains("could not be loaded from"), "fell back or loaded: " + all.Trim());
                }
                finally { Directory.Delete(empty); }
            });

            T.Run("private key read gate toggles", () =>
            {
                FipsModule.SetPrivateKeyReadEnable(true);
                T.True(FipsModule.PrivateKeyReadEnabled, "enabled");
                FipsModule.SetPrivateKeyReadEnable(false);
                T.True(!FipsModule.PrivateKeyReadEnabled, "disabled");
            });

            T.Run("size helper is bound to the loaded libwolfssl binary", () =>
            {
                FipsModule.EnsureHelperMatchesModule();
                Console.WriteLine("        libwolfssl: " + NativeLoader.WolfsslPath);
                T.True(Native.SizeOf((int)FipsStructType.LibCrc) != 0, "no CRC fingerprint");
            });

            T.Run("POSIX cksum matches the cksum utility", () =>
            {
                T.Equal(930766865u, FipsModule.PosixCksum(System.Text.Encoding.ASCII.GetBytes("123456789")), "123456789");
                T.Equal(4294967295u, FipsModule.PosixCksum(Array.Empty<byte>()), "empty");
                T.Equal(2610763910u, FipsModule.PosixCksum(new byte[1000]), "1000 zeros");
            });

            T.Section("Native size helper");

            foreach (string s in new[] { "Rng", "Aes", "Rsa", "Ecc", "Dh", "Sha", "Sha224",
                                         "Sha256", "Sha384", "Sha512", "Sha3", "Hmac", "Cmac" })
            {
                string name = s;
                T.Run("sizeof(" + name + ") available", () =>
                {
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
