/*
   BLAKE2 reference source code package - reference C implementations

   Written in 2012 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/
/* blake2-impl.h
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#pragma once
#ifndef CTAOCRYPT_BLAKE2_IMPL_H
#define CTAOCRYPT_BLAKE2_IMPL_H

#include <cyassl/ctaocrypt/types.h>
#include <stdint.h>

static inline uint32_t load32( const void *src )
{
#if defined(LITTLE_ENDIAN_ORDER)
  return *( uint32_t * )( src );
#else
  const uint8_t *p = ( uint8_t * )src;
  uint32_t w = *p++;
  w |= ( uint32_t )( *p++ ) <<  8;
  w |= ( uint32_t )( *p++ ) << 16;
  w |= ( uint32_t )( *p++ ) << 24;
  return w;
#endif
}

static inline uint64_t load64( const void *src )
{
#if defined(LITTLE_ENDIAN_ORDER)
  return *( uint64_t * )( src );
#else
  const uint8_t *p = ( uint8_t * )src;
  uint64_t w = *p++;
  w |= ( uint64_t )( *p++ ) <<  8;
  w |= ( uint64_t )( *p++ ) << 16;
  w |= ( uint64_t )( *p++ ) << 24;
  w |= ( uint64_t )( *p++ ) << 32;
  w |= ( uint64_t )( *p++ ) << 40;
  w |= ( uint64_t )( *p++ ) << 48;
  w |= ( uint64_t )( *p++ ) << 56;
  return w;
#endif
}

static inline void store32( void *dst, uint32_t w )
{
#if defined(LITTLE_ENDIAN_ORDER)
  *( uint32_t * )( dst ) = w;
#else
  uint8_t *p = ( uint8_t * )dst;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w;
#endif
}

static inline void store64( void *dst, uint64_t w )
{
#if defined(LITTLE_ENDIAN_ORDER)
  *( uint64_t * )( dst ) = w;
#else
  uint8_t *p = ( uint8_t * )dst;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w;
#endif
}

static inline uint64_t load48( const void *src )
{
  const uint8_t *p = ( const uint8_t * )src;
  uint64_t w = *p++;
  w |= ( uint64_t )( *p++ ) <<  8;
  w |= ( uint64_t )( *p++ ) << 16;
  w |= ( uint64_t )( *p++ ) << 24;
  w |= ( uint64_t )( *p++ ) << 32;
  w |= ( uint64_t )( *p++ ) << 40;
  return w;
}

static inline void store48( void *dst, uint64_t w )
{
  uint8_t *p = ( uint8_t * )dst;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w;
}

static inline uint32_t rotl32( const uint32_t w, const unsigned c )
{
  return ( w << c ) | ( w >> ( 32 - c ) );
}

static inline uint64_t rotl64( const uint64_t w, const unsigned c )
{
  return ( w << c ) | ( w >> ( 64 - c ) );
}

static inline uint32_t rotr32( const uint32_t w, const unsigned c )
{
  return ( w >> c ) | ( w << ( 32 - c ) );
}

static inline uint64_t rotr64( const uint64_t w, const unsigned c )
{
  return ( w >> c ) | ( w << ( 64 - c ) );
}

/* prevents compiler optimizing out memset() */
static inline void secure_zero_memory( void *v, size_t n )
{
  volatile uint8_t *p = ( volatile uint8_t * )v;

  while( n-- ) *p++ = 0;
}

#endif  /* CTAOCRYPT_BLAKE2_IMPL_H */

