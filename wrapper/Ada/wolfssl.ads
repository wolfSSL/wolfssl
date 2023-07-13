-- wolfssl.ads
--
-- Copyright (C) 2006-2023 wolfSSL Inc.
--
-- This file is part of wolfSSL.
--
-- wolfSSL is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- wolfSSL is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
--

with Interfaces.C;

--  This package is annotated "with SPARK_Mode" that SPARK can verify
--  the API of this package is used correctly.
package WolfSSL with SPARK_Mode is

   procedure Finalize;
   --  Must be called before application exit.

   Initialization_Error : exception;
   --  Raised if error was encountered during initialization of the
   --  WolfSSL library. The WolfSSL libray is initialized during
   --  elaboration time.

   Cleanup_Error : exception;
   --  Raised if error was encountered during application shutdown
   --  and cleanup of resources allocated by WolfSSL has failed.

   subtype char_array is Interfaces.C.char_array;  --  Remove?

   subtype Byte_Type  is Interfaces.C.char;
   subtype Byte_Index is Interfaces.C.size_t range 0 .. 16_000;
   subtype Byte_Array is Interfaces.C.char_array;

   type Subprogram_Result is (Success, Failure);

   type Context_Type is limited private;

   function Is_Valid (Context : Context_Type) return Boolean;

   type Method_Type is limited private;

   function TLSv1_2_Server_Method return Method_Type;
   function TLSv1_3_Server_Method return Method_Type;
   function TLSv1_3_Client_Method return Method_Type;

   procedure Create_Context (Method  : Method_Type;
                             Context : out Context_Type);
   --  Create and initialize a WolfSSL context.
   --  If successful Is_Valid (Context) = True, otherwise False.

   procedure Free (Context : in out Context_Type) with
      Pre  => Is_Valid (Context),
      Post => not Is_Valid (Context);

   type Mode_Type is private;

   function "&" (Left, Right : Mode_Type) return Mode_Type;

   Verify_None : constant Mode_Type;

   Verify_Peer : constant Mode_Type;

   Verify_Fail_If_No_Peer_Cert : constant Mode_Type;

   Verify_Client_Once : constant Mode_Type;

   Verify_Post_Handshake : constant Mode_Type;

   Verify_Fail_Except_Psk : constant Mode_Type;

   Verify_Default : constant Mode_Type;

   procedure Set_Verify (Context : Context_Type;
                         Mode    : Mode_Type) with
      Pre => Is_Valid (Context);

   type File_Format is private;

   Format_Asn1    : constant File_Format;
   Format_Pem     : constant File_Format;
   Format_Default : constant File_Format;

   function Use_Certificate_File (Context : Context_Type;
                                  File    : String;
                                  Format  : File_Format)
                                  return Subprogram_Result with
      Pre => Is_Valid (Context);

   function Use_Certificate_Buffer (Context : Context_Type;
                                    Input   : char_array;
                                    Format  : File_Format)
                                    return Subprogram_Result with
      Pre => Is_Valid (Context);

   function Use_Private_Key_File (Context : Context_Type;
                                  File    : String;
                                  Format  : File_Format)
                                  return Subprogram_Result with
      Pre => Is_Valid (Context);

   function Use_Private_Key_Buffer (Context : Context_Type;
                                    Input   : Byte_Array;
                                    Format  : File_Format)
                                    return Subprogram_Result with
      Pre => Is_Valid (Context);

   function Load_Verify_Locations (Context : Context_Type;
                                   File    : String;
                                   Path    : String)
                                   return Subprogram_Result with
      Pre => Is_Valid (Context);

   function Load_Verify_Buffer (Context : Context_Type;
                                Input   : Byte_Array;
                                Format  : File_Format)
                                return Subprogram_Result with
      Pre => Is_Valid (Context);

   type WolfSSL_Type is limited private;

   function Is_Valid (Ssl : WolfSSL_Type) return Boolean;

   procedure Create_WolfSSL (Context : Context_Type;
                             Ssl     : out WolfSSL_Type) with
      Pre => Is_Valid (Context);


   function Use_Certificate_File (Ssl     : WolfSSL_Type;
                                  File    : String;
                                  Format  : File_Format)
                                  return Subprogram_Result with
      Pre => Is_Valid (Ssl);

   function Use_Certificate_Buffer (Ssl     : WolfSSL_Type;
                                    Input   : char_array;
                                    Format  : File_Format)
                                    return Subprogram_Result with
      Pre => Is_Valid (Ssl);

   function Use_Private_Key_File (Ssl     : WolfSSL_Type;
                                  File    : String;
                                  Format  : File_Format)
                                  return Subprogram_Result with
      Pre => Is_Valid (Ssl);

   function Use_Private_Key_Buffer (Ssl     : WolfSSL_Type;
                                    Input   : Byte_Array;
                                    Format  : File_Format)
                                    return Subprogram_Result with
      Pre => Is_Valid (Ssl);

   --  Attach wolfSSL to the socket.
   function Attach (Ssl    : WolfSSL_Type;
                    Socket : Integer)
                    return Subprogram_Result with
      Pre => Is_Valid (Ssl);

   procedure Keep_Arrays (Ssl : WolfSSL_Type) with
      Pre => Is_Valid (Ssl);
   --  Don't free temporary arrays at end of handshake.

   procedure Free_Arrays (Ssl : WolfSSL_Type) with
      Pre => Is_Valid (Ssl);
   --  User doesn't need temporary arrays anymore, Free.

   function Accept_Connection (Ssl : WolfSSL_Type)
                               return Subprogram_Result with
      Pre => Is_Valid (Ssl);

   --  This record type has discriminants with default values to be able
   --  to compile this code under the restriction no secondary stack.
   type Read_Result (Result : Subprogram_Result := Failure;
                     Last   : Byte_Index := Byte_Index'Last) is record
      case Result is
         when Success => Buffer : Byte_Array (1 .. Last);
         when Failure => null;
      end case;
   end record;

   function Read (Ssl : WolfSSL_Type) return Read_Result with
      Pre => Is_Valid (Ssl);

   --  The number of bytes written is returned.
   function Write (Ssl  : WolfSSL_Type;
                   Data : Byte_Array) return Integer with
      Pre => Is_Valid (Ssl);

   function Shutdown (Ssl : WolfSSL_Type) return Subprogram_Result with
      Pre => Is_Valid (Ssl);

   procedure Free (Ssl : in out WolfSSL_Type) with
      Pre  => Is_Valid (Ssl),
      Post => not Is_Valid (Ssl);

   function Connect (Ssl : WolfSSL_Type) return Subprogram_Result with
      Pre => Is_Valid (Ssl);

private
   pragma SPARK_Mode (Off);

   subtype int is Interfaces.C.int; use type int;

   type Opaque_Method  is limited null record;
   type Opaque_Context is limited null record;
   type Opaque_WolfSSL is limited null record;

   --  Access-to-object types with convention C uses the same amount of
   --  memory for storing pointers as is done in the C programming
   --  language. The following access type definitions are used in
   --  the Ada binding to the WolfSSL library:
   type Context_Type is access Opaque_Context with Convention => C;
   type Method_Type  is access Opaque_Method  with Convention => C;
   type WolfSSL_Type is access Opaque_WolfSSL with Convention => C;

   subtype Unsigned_32 is Interfaces.Unsigned_32; use type Unsigned_32;

   type Mode_Type is new Unsigned_32;

   --  The following imported subprograms are used to initialize
   --  the constants defined in the public part of this package
   --  specification. They cannot therefore be moved to the body
   --  of this package.

   function WolfSSL_Verify_None return int with
     Convention    => C,
     External_Name => "get_wolfssl_verify_none",
     Import        => True;

   function WolfSSL_Verify_Peer return int with
     Convention    => C,
     External_Name => "get_wolfssl_verify_peer",
     Import        => True;

   function WolfSSL_Verify_Fail_If_No_Peer_Cert return int with
     Convention    => C,
     External_Name => "get_wolfssl_verify_fail_if_no_peer_cert",
     Import        => True;

   function WolfSSL_Verify_Client_Once return int with
     Convention    => C,
     External_Name => "get_wolfssl_verify_client_once",
     Import        => True;

   function WolfSSL_Verify_Post_Handshake return int with
     Convention    => C,
     External_Name => "get_wolfssl_verify_post_handshake",
     Import        => True;

   function WolfSSL_Verify_Fail_Except_Psk return int with
     Convention    => C,
     External_Name => "get_wolfssl_verify_fail_except_psk",
     Import        => True;

   function WolfSSL_Verify_Default return int with
     Convention    => C,
     External_Name => "get_wolfssl_verify_default",
     Import        => True;

   Verify_None : constant Mode_Type := Mode_Type (WolfSSL_Verify_None);
   Verify_Peer : constant Mode_Type := Mode_Type (WolfSSL_Verify_Peer);

   Verify_Fail_If_No_Peer_Cert : constant Mode_Type :=
     Mode_Type (WolfSSL_Verify_Fail_If_No_Peer_Cert);

   Verify_Client_Once : constant Mode_Type :=
     Mode_Type (WolfSSL_Verify_Client_Once);

   Verify_Post_Handshake : constant Mode_Type :=
     Mode_Type (WolfSSL_Verify_Post_Handshake);

   Verify_Fail_Except_Psk : constant Mode_Type :=
     Mode_Type (WolfSSL_Verify_Fail_Except_Psk);

   Verify_Default : constant Mode_Type :=
     Mode_Type (WolfSSL_Verify_Default);

   type File_Format is new Unsigned_32;

   function WolfSSL_Filetype_Asn1 return int with
     Convention    => C,
     External_Name => "get_wolfssl_filetype_asn1",
     Import        => True;

   function WolfSSL_Filetype_Pem return int with
     Convention    => C,
     External_Name => "get_wolfssl_filetype_pem",
     Import        => True;

   function WolfSSL_Filetype_Default return int with
     Convention    => C,
     External_Name => "get_wolfssl_filetype_default",
     Import        => True;

   Format_Asn1 : constant File_Format :=
     File_Format (WolfSSL_Filetype_Asn1);

   Format_Pem : constant File_Format :=
     File_Format (WolfSSL_Filetype_Pem);

   Format_Default : constant File_Format :=
     File_Format (WolfSSL_Filetype_Default);

end WolfSSL;
