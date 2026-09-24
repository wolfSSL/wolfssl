/* FipsObject.cs
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
    /* Base class for wrapper objects that own a native wolfCrypt structure.
     * The memory is a FipsHandle (SafeHandle) sized by the native size
     * helper. Derived classes register the module's free routine with
     * SetNativeFree after a successful initialization; releasing the handle
     * runs it, then zeroes and frees the structure's memory (see FipsHandle
     * for what a refused free leaves behind). The SafeHandle keeps the
     * structure alive across every P/Invoke that uses it. */
    public abstract class FipsObject : IDisposable
    {
        internal FipsHandle Handle { get; }

        internal FipsObject(FipsStructType type)
        {
            Handle = new FipsHandle(StructSize(type));
            /* Aes and Hmac are keyed without an init call (the boundary has
             * no wc_AesInit_fips / wc_HmacInit_fips). In WOLF_CRYPTO_CB
             * builds their devId must be INVALID_DEVID, as those init
             * routines would set it; zero-filled memory would route the
             * operations to crypto callback device 0. */
            FipsStructType devIdAt = type == FipsStructType.Aes ? FipsStructType.AesDevIdOffset
                                   : type == FipsStructType.Hmac ? FipsStructType.HmacDevIdOffset
                                   : (FipsStructType)(-1);
            if ((int)devIdAt >= 0) {
                int off = Native.SizeOf((int)devIdAt);
                if (off > 0)
                    Handle.WriteInt32(off, INVALID_DEVID);
            }
        }

        internal const int INVALID_DEVID = -2;

        internal static int StructSize(FipsStructType type)
        {
            FipsModule.EnsureHelperMatchesModule();
            int sz = Native.SizeOf((int)type);
            if (sz <= 0)
                throw new NotSupportedException(type + " is not available in this wolfSSL build");
            return sz;
        }

        /* Registers the wc_*Free_fips routine for the initialized structure. */
        internal void SetNativeFree(Func<IntPtr, int> freeRoutine) => Handle.SetFree(freeRoutine);

        /* Free routines that return void cannot be refused. */
        internal void SetNativeFree(Action<IntPtr> freeRoutine) =>
            Handle.SetFree(p => { freeRoutine(p); return 0; });

        internal void ThrowIfDisposed()
        {
            if (Handle.IsClosed)
                throw new ObjectDisposedException(GetType().Name);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
                Handle.Dispose();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
