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

namespace wolfSSL.CSharp.Fips
{
    /* Base for objects owning a native structure (FipsHandle sized by the size helper).
     * Derived classes call SetNativeFree after a successful init. */
    public abstract class FipsObject : IDisposable
    {
        internal FipsHandle Handle { get; }

        internal FipsObject(FipsStructType type)
        {
            Handle = new FipsHandle(StructSize(type));
        }

        internal static int StructSize(FipsStructType type)
        {
            FipsModule.EnsureHelperMatchesModule();
            int sz = Native.SizeOf((int)type);
            if (sz <= 0)
            {
                throw new NotSupportedException(type + " is not available in this wolfSSL build");
            }

            return sz;
        }

        /* Secrets returned to callers are pinned, so the GC cannot leave moved,
         * unzeroed copies before the caller zeroes them. */
        internal static byte[] PinnedCopy(byte[] src, int offset, int len)
        {
            byte[] dst = GC.AllocateArray<byte>(len, pinned: true);
            Array.Copy(src, offset, dst, 0, len);
            return dst;
        }

        /* Registers the wc_*Free_fips routine for the initialized structure. */
        internal void SetNativeFree(Func<IntPtr, int> freeRoutine) => Handle.SetFree(freeRoutine);

        /* Free routines that return void cannot be refused. */
        internal void SetNativeFree(Action<IntPtr> freeRoutine) =>
            Handle.SetFree(p => { freeRoutine(p); return 0; });

        internal void ThrowIfDisposed()
        {
            if (Handle.IsClosed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                Handle.Dispose();
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
