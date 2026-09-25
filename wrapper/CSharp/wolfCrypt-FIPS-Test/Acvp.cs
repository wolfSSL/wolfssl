/* Acvp.cs
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
using System.IO;
using System.Linq;
using System.Text.Json;

namespace wolfSSL.CSharp.Fips.Test
{
    /* Loads NIST ACVP known-answer vectors from the wolfACVP aegisolve set
     * (fips/wolfACVP/140-3-known-aegisolve and -expected), the same vectors
     * the FIPS harness runs.
     *
     * The vectors are read at runtime from WOLFACVP_VECTORS, the path to the
     * fips/wolfACVP directory of a FIPS bundle; they are not copied into this
     * repository. When the variable is not set, ACVP tests report SKIP. */
    internal sealed class AcvpVectorSet
    {
        public string Algorithm = "";
        public string File = "";
        public JsonElement Request;
        /* expected test results keyed by (tgId, tcId) */
        public Dictionary<(int, int), JsonElement> Expected = new();

        public IEnumerable<JsonElement> Groups =>
            Request.GetProperty("testGroups").EnumerateArray();

        public JsonElement ExpectedFor(JsonElement group, JsonElement test) =>
            Expected[(group.GetProperty("tgId").GetInt32(), test.GetProperty("tcId").GetInt32())];
    }

    internal static class Acvp
    {
        private const string RequestDir = "140-3-known-aegisolve";
        private const string ExpectedDir = "140-3-known-aegisolve-expected";

        public static string? Root =>
            Environment.GetEnvironmentVariable("WOLFACVP_VECTORS");

        /* request file -> algorithm name, built once per run: each request
         * file is parsed a single time to index it, and Load then parses
         * only the files for its algorithm. */
        private static Dictionary<string, List<string>>? index;

        private static Dictionary<string, List<string>> Index(string reqDir)
        {
            if (index != null)
            {
                return index;
            }

            var map = new Dictionary<string, List<string>>();
            foreach (string req in Directory.GetFiles(reqDir, "*-request.json").OrderBy(f => f))
            {
                using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(req));
                string alg = doc.RootElement[1].GetProperty("algorithm").GetString() ?? "";
                if (!map.TryGetValue(alg, out var files))
                {
                    map[alg] = files = new List<string>();
                }

                files.Add(req);
            }
            return index = map;
        }

        /* All vector sets whose algorithm name matches exactly. Skips the
         * calling test only when WOLFACVP_VECTORS is unset; a path that is
         * set but wrong fails, so an ACVP run cannot pass without vectors. */
        public static List<AcvpVectorSet> Load(string algorithm)
        {
            string? root = Root;
            if (string.IsNullOrEmpty(root))
            {
                T.Skip("WOLFACVP_VECTORS not set (path to fips/wolfACVP)");
            }

            string reqDir = Path.Combine(root!, RequestDir);
            string expDir = Path.Combine(root!, ExpectedDir);
            if (!Directory.Exists(reqDir) || !Directory.Exists(expDir))
            {
                throw new Exception("WOLFACVP_VECTORS is set but " + RequestDir + " / " + ExpectedDir +
                                    " were not found under " + root);
            }

            var sets = new List<AcvpVectorSet>();
            foreach (string req in Index(reqDir).GetValueOrDefault(algorithm) ?? new List<string>())
            {
                JsonElement body;
                using (JsonDocument reqDoc = JsonDocument.Parse(File.ReadAllText(req)))
                {
                    body = reqDoc.RootElement[1].Clone();
                }

                string expName = Path.GetFileName(req).Replace("-request.json", "-expected.json");
                string exp = Path.Combine(expDir, expName);
                if (!File.Exists(exp))
                {
                    throw new Exception("missing expected file " + expName);
                }

                var set = new AcvpVectorSet
                {
                    Algorithm = algorithm,
                    File = Path.GetFileName(req),
                    Request = body
                };
                using JsonDocument expDoc = JsonDocument.Parse(File.ReadAllText(exp));
                JsonElement expBody = expDoc.RootElement[1].Clone();
                foreach (JsonElement g in expBody.GetProperty("testGroups").EnumerateArray())
                {
                    foreach (JsonElement t in g.GetProperty("tests").EnumerateArray())
                    {
                        set.Expected[(g.GetProperty("tgId").GetInt32(), t.GetProperty("tcId").GetInt32())] = t;
                    }
                }

                sets.Add(set);
            }
            if (sets.Count == 0)
            {
                throw new Exception("no ACVP vector sets for " + algorithm);
            }

            return sets;
        }

        public static byte[] Hex(JsonElement e, string name) =>
            Convert.FromHexString(e.GetProperty(name).GetString() ?? "");
    }
}
