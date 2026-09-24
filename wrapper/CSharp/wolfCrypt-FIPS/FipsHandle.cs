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

namespace wolfSSL.CSharp.Fips
{
    /* Owns the unmanaged memory of one native wolfCrypt structure.
     *
     * Passing this SafeHandle (rather than a raw IntPtr) to a P/Invoke makes
     * the marshaller add a reference for the duration of the call, so the
     * structure cannot be freed by a finalizer or by Dispose on another
     * thread while the module is using it. ReleaseHandle runs the module's
     * free routine (if one was registered), then zeroes and frees the
     * structure's own memory.
     *
     * The module refuses its RNG, RSA, ECC and DH free routines once it is
     * in the FAILED state or the algorithm's CAST has failed. Memory the
     * module allocated behind the structure (for example the Hash_DRBG
     * state of a WC_RNG) is then neither zeroized nor freed, and the
     * boundary offers no other way to reach it. The refusal is counted in
     * FipsModule.RefusedFreeCount. */
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

        /* Registers the wc_*Free_fips routine once the structure has been
         * initialized by the module. It receives the raw pointer, runs when
         * the handle is released and returns the module's result (0 for
         * routines that return void). */
        internal void SetFree(Func<IntPtr, int> freeRoutine) => free = freeRoutine;

        /* Writes a field of the structure before it is handed to the
         * module (see FipsObject). */
        internal void WriteInt32(int offset, int value)
        {
            if (offset < 0 || offset > size - sizeof(int))
                throw new ArgumentOutOfRangeException(nameof(offset));
            Marshal.WriteInt32(handle, offset, value);
        }

        private void Clear()
        {
            unsafe { new Span<byte>((void*)handle, size).Clear(); }
        }

        protected override bool ReleaseHandle()
        {
            try {
                int ret = free?.Invoke(handle) ?? 0;
                if (ret != 0)
                    FipsModule.NoteRefusedFree();
            }
            catch {
                /* never throw from release; memory is still zeroed below */
            }
            finally {
                Clear();
                Marshal.FreeHGlobal(handle);
            }
            return true;
        }
    }
}
