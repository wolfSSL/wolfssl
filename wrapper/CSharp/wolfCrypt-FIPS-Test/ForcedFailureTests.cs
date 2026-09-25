/* ForcedFailureTests.cs
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
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace wolfSSL.CSharp.Fips.Test
{
    /* Negative tests: force the module into the FAILED or DEGRADED state
     * with wolfCrypt_SetStatus_fips (HAVE_FORCE_FIPS_FAILURE builds only)
     * and check every wrapper service against it.
     *
     * A forced failure cannot be undone within a process, so each scenario
     * runs in a child process ("--force <code>").
     *
     * FAILED (-203): every service must throw FIPS_NOT_ALLOWED_E.
     *
     * DEGRADED (CAST codes): wolfCrypt_SetStatus_fips marks the CASTs for
     * the code as failed, then EnterDegradedMode resets every passing CAST
     * and re-runs them all, so CASTs that depend on a failed primitive fail
     * too (for example the RSA CAST hashes with SHA-256, the ECDSA CAST
     * uses the DRBG). The test checks that the injected CASTs failed, reads
     * the resulting CAST states from the module, and requires the wrapper
     * to refuse every operation that depends on a CAST in the FAILURE
     * state (the AlgoAllowed() checks of its _fips functions, fips.c).
     * Operations the module refuses beyond that are its own, stricter
     * decision and are reported, not failed. Operations that consume DRBG
     * output are listed when the DRBG CAST has failed. */
    internal static class ForcedFailureTests
    {
        private const int IN_CORE = -203;
        /* DRBG continuous test failure: the module refuses every service
         * (FipsAllowed) while the mode stays NORMAL and the status reports
         * DRBG_CONT_FIPS_E. */
        private const int DRBG_CONT = -209;

        /* Code -> CASTs it degrades (wolfCrypt_SetStatus_fips, v5.2.x). */
        private static readonly Dictionary<int, string[]> Degrades = new()
        {
            [-204] = new[] { "AES_GCM", "AES_CBC" },
            [-206] = new[] { "HMAC_SHA1", "HMAC_SHA2_256", "HMAC_SHA2_512", "HMAC_SHA3_256" },
            [-207] = new[] { "RSA" },
            [-208] = new[] { "DRBG" },
            [-210] = new[] { "AES_GCM" },
            [-242] = new[] { "ECC_CDH" },
            [-254] = new[] { "RSA" },
            [-255] = new[] { "ECDSA" },
            [-256] = new[] { "DH" },
            [-257] = new[] { "AES_GCM", "AES_CBC" },
            [-258] = new[] { "HMAC_SHA3_256" },
            [-259] = new[] { "ECC_PRIMITIVE_Z" },
            [-280] = new[] { "ECDSA" },
            [-281] = new[] { "RSA" },
            [-282] = new[] { "KDF_TLS12" },
            [-283] = new[] { "KDF_TLS13" },
            [-284] = new[] { "KDF_SSH" },
            [-285] = new[] { "DH" },
            [-286] = new[] { "ECC_PRIMITIVE_Z" },
            [-287] = new[] { "RSA", "ECDSA", "DH" },
        };

        /* CAST names used above -> module CAST ids */
        private static readonly Dictionary<string, FipsCast> CastIds = new()
        {
            ["AES_CBC"] = FipsCast.AesCbc,
            ["AES_GCM"] = FipsCast.AesGcm,
            ["HMAC_SHA1"] = FipsCast.HmacSha1,
            ["HMAC_SHA2_256"] = FipsCast.HmacSha2_256,
            ["HMAC_SHA2_512"] = FipsCast.HmacSha2_512,
            ["HMAC_SHA3_256"] = FipsCast.HmacSha3_256,
            ["DRBG"] = FipsCast.Drbg,
            ["RSA"] = FipsCast.RsaSignPkcs1v15,
            ["ECC_PRIMITIVE_Z"] = FipsCast.EccPrimitiveZ,
            ["ECDSA"] = FipsCast.Ecdsa,
            ["DH"] = FipsCast.DhPrimitiveZ,
            ["KDF_TLS12"] = FipsCast.KdfTls12,
            ["KDF_TLS13"] = FipsCast.KdfTls13,
            ["KDF_SSH"] = FipsCast.KdfSsh,
            ["ECC_CDH"] = FipsCast.EccCdh,
        };

        /* ---- parent ---- */

        public static void Run()
        {
            T.Section("Forced failure (FAILED and DEGRADED modes)");
            if (!FipsModule.CanInjectFailure)
            {
                T.Run("forced failure scenarios", () =>
                    T.Skip("library not built with HAVE_FORCE_FIPS_FAILURE (use the optest build)"));
                return;
            }
            foreach (int code in new[] { IN_CORE, DRBG_CONT }.Concat(Degrades.Keys))
            {
                int c = code;
                string label = code == IN_CORE ? "FAILED" : code == DRBG_CONT ? "CONTINUOUS TEST" : "DEGRADED";
                T.Run(label + " " + FipsError.Name(c) + " (" + c + ")", () => RunChild(c));
            }
        }

        private static void RunChild(int code)
        {
            string exe = Environment.ProcessPath!;
            var psi = new ProcessStartInfo(exe)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            if (Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            {
                psi.ArgumentList.Add(typeof(ForcedFailureTests).Assembly.Location);
            }

            psi.ArgumentList.Add("--force");
            psi.ArgumentList.Add(code.ToString());
            using var p = Process.Start(psi)!;
            /* read both streams concurrently so neither pipe can fill and
             * block the child, and so the timeout below can fire */
            var outTask = p.StandardOutput.ReadToEndAsync();
            var errTask = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(600_000))
            {
                p.Kill(entireProcessTree: true);
                p.WaitForExit();
                throw new Exception("child timed out");
            }
            string stdout = outTask.GetAwaiter().GetResult();
            string stderr = errTask.GetAwaiter().GetResult();
            var results = stdout.Split('\n').Where(l => l.StartsWith("RESULT ")).ToList();
            foreach (var l in results.Where(l => l.StartsWith("RESULT FAIL")))
            {
                Console.WriteLine("        " + l);
            }

            foreach (var s in stdout.Split('\n').Where(l => l.StartsWith("SUMMARY ")))
            {
                Console.WriteLine("        " + s.Substring(8).Trim());
            }

            if (p.ExitCode != 0)
            {
                throw new Exception("child exit " + p.ExitCode + (results.Count == 0 ? ": " + stderr.Trim() : ""));
            }
        }

        /* ---- child ---- */

        private sealed class Op
        {
            public string Name = "";
            public string[] Casts = Array.Empty<string>();
            public Action Run = () => { };
            public bool UsesDrbg;
        }

        public static int Child(int code)
        {
            /* The callback records every delivery and throws on purpose: the
             * wrapper's trampoline must swallow it (an exception unwinding
             * into the module would terminate the process). */
            var callbacks = new List<(int Ok, int Err)>();
            FipsModule.Initialize(onFailure: (ok, err, hash) =>
            {
                lock (callbacks)
                {
                    callbacks.Add((ok, err));
                }

                throw new InvalidOperationException("failure callback throws on purpose");
            });
            var rng = new FipsRng();
            var aesKey = new byte[16];
            var cbc = FipsAes.CreateCbc(aesKey, new byte[16], true);
            var ctr = FipsAes.CreateCtr(aesKey, new byte[16]);
            var gcm = new FipsAesGcm(aesKey);
            gcm.UseInternalIV(rng);
            var ccm = new FipsAesCcm(aesKey);
            ccm.SetNonce(new byte[12]);
            var hmacKey = new byte[32];
            var cmacPending = new FipsCmac(aesKey);   /* finalized only after injection */
            cmacPending.Update(new byte[3]);
            var rsa = FipsRsaKey.Generate(2048, rng);
            byte[] d256 = FipsHash.Compute(FipsHashType.Sha256, new byte[] { 1 });
            byte[] rsaSig = Pkcs1.Sign(rsa, FipsHashType.Sha256, d256, rng);
            var ecc = FipsEccKey.Generate(FipsEccCurve.P256, rng);
            var eccPeer = FipsEccKey.Generate(FipsEccCurve.P256, rng);
            byte[] eccPub = eccPeer.ExportPublic();
            byte[] eccSig = ecc.SignHash(FipsHashType.Sha256, d256);
            var dh = new FipsDh(FipsDhGroup.Ffdhe2048);
            var dhA = dh.GenerateKeyPair(rng);
            var dhB = dh.GenerateKeyPair(rng);
            byte[] rsaCt = rsa.Encrypt(new byte[] { 1, 2, 3 }, rng);
            var gcmCt = gcm.Encrypt(new byte[5]);
            var ccmCt = ccm.Encrypt(new byte[5]);
            var spareRng = new FipsRng();

            var ops = new List<Op> {
                new() { Name = "DRBG instantiate", Casts = new[] { "DRBG" }, Run = () => new FipsRng().Dispose() },
                new() { Name = "DRBG generate (existing)", UsesDrbg = true, Casts = new[] { "DRBG" }, Run = () => rng.Generate(16) },
                new() { Name = "SHA-1", Casts = new[] { "HMAC_SHA1" }, Run = () => FipsHash.Compute(FipsHashType.Sha1, new byte[1]) },
                new() { Name = "SHA-256", Casts = new[] { "HMAC_SHA2_256" }, Run = () => FipsHash.Compute(FipsHashType.Sha256, new byte[1]) },
                new() { Name = "SHA-512", Casts = new[] { "HMAC_SHA2_512" }, Run = () => FipsHash.Compute(FipsHashType.Sha512, new byte[1]) },
                new() { Name = "SHA3-256", Casts = new[] { "HMAC_SHA3_256" }, Run = () => FipsHash.Compute(FipsHashType.Sha3_256, new byte[1]) },
                new() { Name = "HMAC-SHA-256", Casts = new[] { "HMAC_SHA2_256" }, Run = () => FipsHmac.Compute(FipsHashType.Sha256, hmacKey, new byte[1]) },
                new() { Name = "HMAC-SHA3-256", Casts = new[] { "HMAC_SHA3_256" }, Run = () => FipsHmac.Compute(FipsHashType.Sha3_256, hmacKey, new byte[1]) },
                new() { Name = "CMAC", Casts = new[] { "AES_CBC" }, Run = () => FipsCmac.Compute(aesKey, new byte[1]) },
                new() { Name = "AES-CBC (existing)", Casts = new[] { "AES_CBC" }, Run = () => cbc.Transform(new byte[16]) },
                new() { Name = "AES-CTR (existing)", Casts = new[] { "AES_CBC" }, Run = () => ctr.Transform(new byte[5]) },
                new() { Name = "AES-GCM encrypt (existing)", Casts = new[] { "AES_CBC", "AES_GCM" }, Run = () => gcm.Encrypt(new byte[5]) },
                new() { Name = "GMAC", UsesDrbg = true, Casts = new[] { "AES_CBC", "AES_GCM" }, Run = () => FipsGmac.Compute(aesKey, new byte[5], rng) },
                new() { Name = "AES-GCM decrypt (existing)", Casts = new[] { "AES_CBC", "AES_GCM" }, Run = () => gcm.Decrypt(gcmCt.IV, gcmCt.Ciphertext, gcmCt.Tag) },
                new() { Name = "AES-CCM encrypt (existing)", Casts = new[] { "AES_CBC" }, Run = () => ccm.Encrypt(new byte[5]) },
                new() { Name = "AES-CCM decrypt (existing)", Casts = new[] { "AES_CBC" }, Run = () => ccm.Decrypt(ccmCt.IV, ccmCt.Ciphertext, ccmCt.Tag) },
                new() { Name = "RSA sign (existing key)", UsesDrbg = true, Casts = new[] { "RSA" }, Run = () => Pkcs1.Sign(rsa, FipsHashType.Sha256, d256, rng) },
                new() { Name = "RSA verify (existing key)", Casts = new[] { "RSA" }, Run = () => Require(Pkcs1.Verify(rsa, FipsHashType.Sha256, d256, rsaSig)) },
                new() { Name = "RSA OAEP decrypt (existing key)", Casts = new[] { "RSA" }, Run = () => rsa.Decrypt(rsaCt) },
                new() { Name = "RSA key generation", UsesDrbg = true, Casts = new[] { "RSA" }, Run = () => FipsRsaKey.Generate(2048, rng).Dispose() },
                new() { Name = "ECDSA sign (existing key)", UsesDrbg = true, Casts = new[] { "ECDSA" }, Run = () => ecc.SignHash(FipsHashType.Sha256, d256) },
                new() { Name = "ECDSA verify (existing key)", Casts = new[] { "ECDSA" }, Run = () => Require(ecc.VerifyHash(FipsHashType.Sha256, d256, eccSig)) },
                new() { Name = "ECC key generation", UsesDrbg = true, Casts = new[] { "ECDSA" }, Run = () => FipsEccKey.Generate(FipsEccCurve.P256, rng).Dispose() },
                new() { Name = "ECC public import", Casts = new[] { "ECDSA" }, Run = () => FipsEccKey.ImportPublic(FipsEccCurve.P256, eccPub).Dispose() },
                new() { Name = "ECDH shared secret (existing keys)", UsesDrbg = true, Casts = new[] { "ECC_PRIMITIVE_Z" }, Run = () => ecc.SharedSecret(eccPeer) },
                new() { Name = "DH agree (existing keys)", Casts = new[] { "DH" }, Run = () => dh.Agree(dhA.PrivateKey, dhB.PublicKey) },
                new() { Name = "DH key pair generation", UsesDrbg = true, Casts = new[] { "DH" }, Run = () => dh.GenerateKeyPair(rng).Dispose() },
                new() { Name = "DH public key check", Casts = new[] { "DH" }, Run = () => Require(dh.CheckPublicKey(dhB.PublicKey)) },
                new() { Name = "HKDF", Casts = new[] { "HMAC_SHA2_256" }, Run = () => FipsKdf.Hkdf(FipsHashType.Sha256, new byte[32], null, null, 32) },
                new() { Name = "TLS 1.2 PRF", Casts = new[] { "KDF_TLS12" }, Run = () => FipsKdf.Tls12ExtendedMasterSecret(FipsHashType.Sha256, new byte[48], new byte[32]) },
                new() { Name = "TLS 1.3 HKDF expand-label", Casts = new[] { "KDF_TLS13" }, Run = () => FipsKdf.Tls13ExpandLabel(FipsHashType.Sha256, new byte[32], "derived", new byte[32], 32) },
                new() { Name = "SSH KDF", Casts = new[] { "KDF_SSH" }, Run = () => FipsKdf.SshKdf(FipsHashType.Sha256, 'A', new byte[] { 1, 2 }, new byte[32], new byte[32], 16) },
            };

            /* sanity: everything works before the failure is injected */
            int bad = 0;
            foreach (var op in ops)
            {
                if (!Try(op, out string err))
                {
                    Console.WriteLine("RESULT FAIL pre-injection " + op.Name + ": " + err);
                    bad++;
                }
            }

            if (bad > 0)
            {
                return 2;
            }

            int ret = FipsModule.InjectFailure(code);
            if (ret != 0)
            {
                Console.WriteLine("RESULT FAIL wolfCrypt_SetStatus_fips returned " + ret);
                return 3;
            }

            /* every service refused: FAILED mode, or the DRBG continuous
             * test failure (mode stays NORMAL) */
            bool failed = code == IN_CORE || code == DRBG_CONT;
            int pass = 0;
            var extra = new List<string>();

            /* module view of each CAST after injection */
            var castState = CastIds.ToDictionary(kv => kv.Key, kv => FipsModule.GetCastState(kv.Value));
            var degraded = new HashSet<string>(castState.Where(kv => kv.Value == FipsCastState.Failure).Select(kv => kv.Key));
            var unsettled = new HashSet<string>(castState.Where(kv => kv.Value != FipsCastState.Failure &&
                                                                      kv.Value != FipsCastState.Success).Select(kv => kv.Key));

            void Check(bool ok, string what)
            {
                if (ok)
                {
                    pass++;
                }
                else { bad++; Console.WriteLine("RESULT FAIL " + what); }
            }

            if (!failed)
            {
                foreach (string c in Degrades[code])
                {
                    Check(degraded.Contains(c), "injected CAST " + c + " is not in the FAILURE state");
                }

                var cascade = degraded.Except(Degrades[code]).OrderBy(x => x).ToList();
                Console.WriteLine("SUMMARY injected: " + string.Join(", ", Degrades[code]) +
                                  (cascade.Count > 0 ? "; cascade on re-run: " + string.Join(", ", cascade) : "; no cascade"));
            }

            FipsMode mode = FipsModule.Mode;
            FipsMode expectMode = code == IN_CORE ? FipsMode.Failed : code == DRBG_CONT ? FipsMode.Normal : FipsMode.Degraded;
            Check(mode == expectMode, "mode is " + mode + ", expected " + expectMode);
            if (failed)
            {
                Check(FipsModule.Status == code, "status is " + FipsModule.Status);
            }

            Check(!FipsModule.IsOperational, "IsOperational after injection");
            bool initThrew = false;
            try { FipsModule.Initialize(useOsSeed: false); } catch (WolfCryptFipsException) { initThrew = true; }
            Check(initThrew, "Initialize accepted a non-operational module");

            foreach (var op in ops)
            {
                if (!failed && op.Casts.Any(unsettled.Contains) && !op.Casts.Any(degraded.Contains))
                {
                    continue;   /* CAST neither passed nor failed: no expectation */
                }
                /* the wrapper refuses every DRBG consumer once the DRBG CAST
* has failed, including those the module still serves from
* an existing instance (module finding 14) */
                bool expectFail = failed || op.Casts.Any(degraded.Contains) ||
                                  (op.UsesDrbg && degraded.Contains("DRBG"));
                bool ok = Try(op, out string err, out int errCode);
                if (expectFail)
                {
                    Check(!ok, op.Name + ": succeeded, expected refusal");
                    if (failed && !ok)
                    {
                        Check(errCode == FipsError.FIPS_NOT_ALLOWED_E,
                              op.Name + ": expected FIPS_NOT_ALLOWED_E, got " + err);
                    }
                    /* a refusal must be a module-state error, never a plain
* "verification returned false" */
                    if (!failed && !ok)
                    {
                        Check(FipsError.IsModuleStateError(errCode),
                              op.Name + ": refused without a module-state error: " + err);
                    }
                }
                else if (!ok)
                {
                    /* only a module-state refusal is the module's own
                     * stricter decision; anything else (a managed
                     * exception, a verification returning false) is a bug */
                    if (FipsError.IsModuleStateError(errCode))
                    {
                        extra.Add(op.Name + " (" + err + ")");
                    }
                    else
                    {
                        Check(false, op.Name + ": unexpected failure: " + err);
                    }
                }
            }
            /* failure callback delivery: FAILED and continuous-test refusals
             * report (0, code) from FipsAllowed; entering DEGRADED reports
             * (0, code) then (1, FIPS_DEGRADED_E) */
            List<(int Ok, int Err)> seen;
            lock (callbacks)
            {
                seen = new List<(int, int)>(callbacks);
            }

            Check(seen.Contains((0, code)), "failure callback not delivered with (0, " + code + "); got " +
                  string.Join(" ", seen.Select(c => "(" + c.Ok + "," + c.Err + ")")));
            if (!failed)
            {
                Check(seen.Contains((1, FipsError.FIPS_DEGRADED_E)), "failure callback not delivered with (1, FIPS_DEGRADED_E)");
            }

            if (failed)
            {
                /* a refused Generate leaves nothing in the caller's buffer */
                byte[] buf = Enumerable.Repeat((byte)0xAA, 64).ToArray();
                try { rng.Generate(buf); } catch (WolfCryptFipsException) { }
                Check(buf.All(b => b == 0), "refused Generate left data in the caller's buffer");

                /* a refused CMAC Final still ends the object */
                bool cmacRefused = false, ended = false;
                try { cmacPending.Final(); } catch (WolfCryptFipsException) { cmacRefused = true; }
                try { cmacPending.Update(new byte[1]); } catch (InvalidOperationException) { ended = true; }
                Check(cmacRefused && ended, "CMAC usable after a refused Final");
            }

            if (failed)
            {
                /* the module refuses wc_FreeRng_fips here; the wrapper must
                 * report it rather than lose it */
                long before = FipsModule.RefusedFreeCount;
                spareRng.Dispose();
                Check(FipsModule.RefusedFreeCount == before + 1,
                      "refused wc_FreeRng_fips not counted (" + before + " -> " + FipsModule.RefusedFreeCount + ")");
            }
            if (extra.Count > 0)
            {
                Console.WriteLine("SUMMARY also refused by the module: " + string.Join(", ", extra));
            }

            int refused = ops.Count(o => failed || o.Casts.Any(degraded.Contains) ||
                                         (o.UsesDrbg && degraded.Contains("DRBG"))) + extra.Count;
            Console.WriteLine("SUMMARY " + (ops.Count - refused) + " services still available, " + refused +
                              " refused, " + pass + " checks passed, " + bad + " failed");
            return bad == 0 ? 0 : 1;
        }

        private static void Require(bool ok)
        {
            if (!ok)
            {
                throw new Exception("verification returned false");
            }
        }

        private static bool Try(Op op, out string err) => Try(op, out err, out _);

        private static bool Try(Op op, out string err, out int code)
        {
            try
            {
                op.Run();
                err = ""; code = 0;
                return true;
            }
            catch (WolfCryptFipsException e) { err = FipsError.Name(e.Code); code = e.Code; return false; }
            catch (Exception e) { err = e.GetType().Name + ": " + e.Message; code = 0; return false; }
        }
    }
}
