/* FipsHandle.cs
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
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace wolfSSL.CSharp.Fips
{
    /* Owns one native structure. As a SafeHandle it stays referenced during each P/Invoke,
     * so another thread cannot free it mid-call. */
    internal sealed class FipsHandle : SafeHandle
    {
        private readonly int size;
        private Func<IntPtr, int>? free;

        internal FipsHandle(int size) : base(IntPtr.Zero, ownsHandle: true)
        {
            this.size = size;
            SetHandle(Marshal.AllocHGlobal(size));
            Clear();
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        /* Free routine run on release, then memory is zeroed and freed. RNG/RSA/ECC/DH frees
         * are refused after a failure, leaving module memory unzeroized (RefusedFreeCount). */
        internal void SetFree(Func<IntPtr, int> freeRoutine) => free = freeRoutine;

        private void Clear()
        {
            /* ZeroMemory is not removed by the optimizer (Span.Clear has no
             * such guarantee before the memory is freed) */
            unsafe { CryptographicOperations.ZeroMemory(new Span<byte>((void*)handle, size)); }
        }

        protected override bool ReleaseHandle()
        {
            try
            {
                int ret = free?.Invoke(handle) ?? 0;
                if (ret != 0)
                {
                    FipsModule.NoteRefusedFree();
                }
            }
            catch
            {
                /* never throw from release; memory is still zeroed below */
            }
            finally
            {
                Clear();
                Marshal.FreeHGlobal(handle);
            }
            return true;
        }
    }
}
