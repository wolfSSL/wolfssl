; /* aes_asm.asm
;  *
; * Copyright (C) 2006-2026 wolfSSL Inc.
;  *
;  * This file is part of wolfSSL.
;  *
;  * wolfSSL is free software; you can redistribute it and/or modify
;  * it under the terms of the GNU General Public License as published by
;  * the Free Software Foundation; either version 3 of the License, or
;  * (at your option) any later version.
;  *
;  * wolfSSL is distributed in the hope that it will be useful,
;  * but WITHOUT ANY WARRANTY; without even the implied warranty of
;  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;  * GNU General Public License for more details.
;  *
;  * You should have received a copy of the GNU General Public License
;  * along with this program; if not, write to the Free Software
;  * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
;  */



;
;
;  /* See Intel Advanced Encryption Standard (AES) Instructions Set White Paper
;   * by Israel, Intel Mobility Group Development Center, Israel Shay Gueron
;   */
;
;   /* This file is in intel asm syntax, see .s for at&t syntax */
;


fips_version = 0
IFDEF HAVE_FIPS
  fips_version = 1
  IFDEF HAVE_FIPS_VERSION
    fips_version = HAVE_FIPS_VERSION
  ENDIF
ENDIF

IF fips_version GE 2
  fipsAb SEGMENT ALIAS(".fipsA$b") 'CODE'
ELSE
  _text SEGMENT
ENDIF

IF fips_version GE 2
  fipsAb ENDS
ELSE
  _text ENDS
ENDIF

END
