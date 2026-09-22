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
     * Memory is allocated here at the size reported by the native size
     * helper, zeroed, and handed to the module's _fips initializer by the
     * derived class. Dispose calls the derived class free routine, then
     * zeroes and releases the memory. */
    public abstract class FipsObject : IDisposable
    {
        private readonly int size;
        private bool disposed;

        internal IntPtr Handle { get; private set; }

        internal FipsObject(FipsStructType type)
        {
            size = StructSize(type);
            Handle = Marshal.AllocHGlobal(size);
            Zero();
        }

        internal static int StructSize(FipsStructType type)
        {
            int sz = Native.SizeOf((int)type);
            if (sz <= 0)
                throw new NotSupportedException(type + " is not available in this wolfSSL build");
            return sz;
        }

        /* Called by Dispose to release native resources held inside the
         * structure (the wc_*Free_fips routine). */
        protected abstract void FreeNative();

        internal void ThrowIfDisposed()
        {
            if (disposed)
                throw new ObjectDisposedException(GetType().Name);
        }

        private void Zero()
        {
            unsafe { new Span<byte>((void*)Handle, size).Clear(); }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed)
                return;
            disposed = true;
            try {
                FreeNative();
            }
            finally {
                Zero();
                Marshal.FreeHGlobal(Handle);
                Handle = IntPtr.Zero;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~FipsObject()
        {
            Dispose(false);
        }
    }
}
