-- wolfssl.adb
--
-- Copyright (C) 2006-2026 wolfSSL Inc.
--
-- This file is part of wolfSSL.
--
-- wolfSSL is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 3 of the License, or
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
with Ada.Unchecked_Conversion;

package body WolfSSL is

   subtype size_t is Interfaces.C.size_t; use type size_t;

   subtype long is Interfaces.C.long;
   subtype unsigned_long is Interfaces.C.unsigned_long;

   --  The first value in the Byte_Type range (Byte_Type'First),
   --  used as the null byte (0).
   nul : constant Byte_Type := Byte_Type'First;

   --  WOLFSSL_SUCCESS : constant int := Get_WolfSSL_Success;

   function Initialize_WolfSSL return int with
     Convention    => C,
     External_Name => "wolfSSL_Init",
     Import        => True;

   function Finalize_WolfSSL return int with
     Convention    => C,
     External_Name => "wolfSSL_Cleanup",
     Import        => True;

   function Initialize return Subprogram_Result is
      Result : constant int := Initialize_WolfSSL;
   begin
      return Subprogram_Result (Result);
   end Initialize;

   function Finalize return Subprogram_Result is
      Result : constant int := Finalize_WolfSSL;
   begin
      return Subprogram_Result (Result);
   end Finalize;

   function Is_Valid (Context : Context_Type) return Boolean is
   begin
      return Context /= null;
   end Is_Valid;

   function Is_Valid (Method : Method_Type) return Boolean is
   begin
      return Method /= null;
   end Is_Valid;

   function WolfTLSv1_2_Server_Method return Method_Type with
     Convention    => C,
     External_Name => "wolfTLSv1_2_server_method",
     Import        => True;

   function TLSv1_2_Server_Method return Method_Type is
   begin
      return WolfTLSv1_2_Server_Method;
   end TLSv1_2_Server_Method;

   function WolfTLSv1_2_Client_Method return Method_Type with
     Convention    => C,
     External_Name => "wolfTLSv1_2_client_method",
     Import        => True;

   function TLSv1_2_Client_Method return Method_Type is
   begin
      return WolfTLSv1_2_Client_Method;
   end TLSv1_2_Client_Method;

   function WolfTLSv1_3_Server_Method return Method_Type with
     Convention    => C,
     External_Name => "wolfTLSv1_3_server_method",
     Import        => True;

   function TLSv1_3_Server_Method return Method_Type is
   begin
      return WolfTLSv1_3_Server_Method;
   end TLSv1_3_Server_Method;

   function WolfTLSv1_3_Client_Method return Method_Type with
     Convention    => C,
     External_Name => "wolfTLSv1_3_client_method",
     Import        => True;

   function TLSv1_3_Client_Method return Method_Type is
   begin
      return WolfTLSv1_3_Client_Method;
   end TLSv1_3_Client_Method;

   function WolfDTLSv1_2_Server_Method return Method_Type with
     Convention    => C,
     External_Name => "wolfDTLSv1_2_server_method",
     Import        => True;

   function DTLSv1_2_Server_Method return Method_Type is
   begin
      return WolfDTLSv1_2_Server_Method;
   end DTLSv1_2_Server_Method;

   function WolfDTLSv1_2_Client_Method return Method_Type with
     Convention    => C,
     External_Name => "wolfDTLSv1_2_client_method",
     Import        => True;

   function DTLSv1_2_Client_Method return Method_Type is
   begin
      return WolfDTLSv1_2_Client_Method;
   end DTLSv1_2_Client_Method;

   function WolfDTLSv1_3_Server_Method return Method_Type with
     Convention    => C,
     External_Name => "wolfDTLSv1_3_server_method",
     Import        => True;

   function DTLSv1_3_Server_Method return Method_Type is
   begin
      return WolfDTLSv1_3_Server_Method;
   end DTLSv1_3_Server_Method;

   function WolfDTLSv1_3_Client_Method return Method_Type with
     Convention    => C,
     External_Name => "wolfDTLSv1_3_client_method",
     Import        => True;

   function DTLSv1_3_Client_Method return Method_Type is
   begin
      return WolfDTLSv1_3_Client_Method;
   end DTLSv1_3_Client_Method;

   function WolfSSL_CTX_new (Method : Method_Type)
                             return Context_Type with
     Convention => C, External_Name => "wolfSSL_CTX_new", Import => True;

   procedure Create_Context (Method  : in out Method_Type;
                             Context : out Context_Type) is
   begin
      Context := WolfSSL_CTX_new (Method);
      Method := null;
   end Create_Context;

   procedure WolfSSL_CTX_free (Context : Context_Type) with
     Convention => C, External_Name => "wolfSSL_CTX_free", Import => True;

   procedure Free (Context : in out Context_Type) is
   begin
      if Context /= null then
         WolfSSL_CTX_free (Context);
      end if;
      Context := null;
   end Free;

   type Opaque_X509_Store_Context is limited null record;
   type X509_Store_Context is access Opaque_X509_Store_Context with
     Convention => C;

   type Verify_Callback is access function
     (A : int;
      Context : X509_Store_Context)
      return int
     with Convention => C;

   procedure WolfSSL_CTX_Set_Verify (Context  : Context_Type;
                                     Mode     : int;
                                     Callback : Verify_Callback) with
     Convention    => C,
     External_Name => "wolfSSL_CTX_set_verify",
     Import        => True;
   --  This function sets the verification method for remote peers and
   --  also allows a verify callback to be registered with the SSL
   --  context. The verify callback will be called only when a
   --  verification failure has occurred. If no verify callback is
   --  desired, the NULL pointer can be used for verify_callback.
   --  The verification mode of peer certificates is a logically OR'd
   --  list of flags. The possible flag values include:
   --  SSL_VERIFY_NONE Client mode: the client will not verify the
   --  certificate received from the server and the handshake will
   --  continue as normal. Server mode: the server will not send a
   --  certificate request to the client. As such, client verification
   --  will not be enabled. SSL_VERIFY_PEER Client mode: the client will
   --  verify the certificate received from the server during the
   --  handshake. This is turned on by default in wolfSSL, therefore,
   --  using this option has no effect. Server mode: the server will send
   --  a certificate request to the client and verify the client
   --  certificate received. SSL_VERIFY_FAIL_IF_NO_PEER_CERT Client mode:
   --  no effect when used on the client side. Server mode:
   --  the verification will fail on the server side if the client fails
   --  to send a certificate when requested to do so (when using
   --  SSL_VERIFY_PEER on the SSL server).
   --  SSL_VERIFY_FAIL_EXCEPT_PSK Client mode: no effect when used on
   --  the client side. Server mode: the verification is the same as
   --  SSL_VERIFY_FAIL_IF_NO_PEER_CERT except in the case of a
   --  PSK connection. If a PSK connection is being made then the
   --  connection will go through without a peer cert.

   function "or" (Left, Right : Mode_Type) return Mode_Type is
      L : constant Unsigned_32 := Unsigned_32 (Left);
      R : constant Unsigned_32 := Unsigned_32 (Right);
   begin
      return Mode_Type (L or R);
   end "or";

   procedure Set_Verify (Context : Context_Type;
                         Mode    : Mode_Type) is
      pragma Warnings (Off, "pragma Restrictions (No_Exception_Propagation)");
      --  The values that Set_Verify may be called with have first
      --  been int values, then converted into Mode_Type values and
      --  here they are converted back to int. This can never fail
      --  unless there is hardware failure or cosmic radiation has
      --  done a bit flip.
      V : constant int := int (Mode);
      pragma Warnings (On, "pragma Restrictions (No_Exception_Propagation)");
   begin
      WolfSSL_CTX_Set_Verify (Context  => Context,
                              Mode     => V,
                              Callback => null);
   end Set_Verify;

   function WolfSSL_Get_Verify (Context : Context_Type) return int with
     Convention    => C,
     External_Name => "wolfSSL_CTX_get_verify_mode",
     Import        => True;

   function Get_Verify (Context : Context_Type) return Mode_Type is
   begin
      return Mode_Type (WolfSSL_Get_Verify (Context));
   end Get_Verify;

   function Use_Certificate_File (Context : Context_Type;
                                  File    : Byte_Array;
                                  Format  : int)
                                  return int with
     Convention    => C,
     External_Name => "wolfSSL_CTX_use_certificate_file",
     Import        => True;

   function Use_Certificate_File (Context : Context_Type;
                                  File    : String;
                                  Format  : File_Format)
                                  return Subprogram_Result is
   begin
      declare
         Ctx : constant Context_Type := Context;
         F : Byte_Array (1 .. File'Length + 1);
         Result : int;
      begin
         for I in File'Range loop
            F (F'First + Byte_Index (I - File'First)) := Byte_Type (File (I));
         end loop;
         F (F'Last) := nul;
         Result := Use_Certificate_File (Ctx, F, int (Format));
         return Subprogram_Result (Result);
      end;
   exception
      when others =>
         return Exception_Error;
   end Use_Certificate_File;

   function Use_Certificate_Buffer (Context : Context_Type;
                                    Input   : Byte_Array;
                                    Size    : long;
                                    Format  : int)
                                    return int with
     Convention    => C,
     External_Name => "wolfSSL_CTX_use_certificate_buffer",
     Import        => True;

   function Use_Certificate_Buffer (Context : Context_Type;
                                    Input   : Byte_Array;
                                    Format  : File_Format)
                                    return Subprogram_Result is
      Result : int;
   begin
      Result := Use_Certificate_Buffer (Context, Input,
                                        Input'Length, int (Format));
      return Subprogram_Result (Result);
   exception
      when others =>
         return Exception_Error;
   end Use_Certificate_Buffer;

   function Use_Private_Key_File (Context : Context_Type;
                                  File    : Byte_Array;
                                  Format  : int)
                                  return int with
     Convention    => C,
     External_Name => "wolfSSL_CTX_use_PrivateKey_file",
     Import        => True;

   function Use_Private_Key_File (Context : Context_Type;
                                  File    : String;
                                  Format  : File_Format)
                                  return Subprogram_Result is
   begin
      declare
         Ctx : constant Context_Type := Context;
         F : Byte_Array (1 .. File'Length + 1);
         Result : int;
      begin
         for I in File'Range loop
            F (F'First + Byte_Index (I - File'First)) := Byte_Type (File (I));
         end loop;
         F (F'Last) := nul;
         Result := Use_Private_Key_File (Ctx, F, int (Format));
         return Subprogram_Result (Result);
      end;
   exception
      when others =>
         return Exception_Error;
   end Use_Private_Key_File;

   function Use_Private_Key_Buffer (Context : Context_Type;
                                    Input   : Byte_Array;
                                    Size    : long;
                                    Format  : int)
                                    return int with
     Convention    => C,
     External_Name => "wolfSSL_CTX_use_PrivateKey_buffer",
     Import        => True;

   function Use_Private_Key_Buffer (Context : Context_Type;
                                    Input   : Byte_Array;
                                    Format  : File_Format)
                                    return Subprogram_Result is
      Result : int;
   begin
      Result := Use_Private_Key_Buffer (Context, Input,
                                        Input'Length, int (Format));
      return Subprogram_Result (Result);
   exception
      when others =>
         return Exception_Error;
   end Use_Private_Key_Buffer;

   function Load_Verify_Locations1
     (Context : Context_Type;
      File    : Byte_Array;
      Path    : Byte_Array) return int with
     Convention    => C,
     External_Name => "wolfSSL_CTX_load_verify_locations",
     Import        => True;
   --  This function loads PEM-formatted CA certificate files into
   --  the SSL context (WOLFSSL_CTX). These certificates will be treated
   --  as trusted root certificates and used to verify certs received
   --  from peers during the SSL handshake. The root certificate file,
   --  provided by the file argument, may be a single certificate or a
   --  file containing multiple certificates. If multiple CA certs are
   --  included in the same file, wolfSSL will load them in the same order
   --  they are presented in the file. The path argument is a pointer to
   --  the name of a directory that contains certificates of trusted
   --  root CAs. If the value of file is not NULL, path may be specified
   --  as NULL if not needed. If path is specified and NO_WOLFSSL_DIR was
   --  not defined when building the library, wolfSSL will load all
   --  CA certificates located in the given directory. This function will
   --  attempt to load all files in the directory. This function expects
   --  PEM formatted CERT_TYPE file with header "--BEGIN CERTIFICATE--".

   function Load_Verify_Locations2
     (Context : Context_Type;
      File    : Byte_Array;
      Path    : access Interfaces.C.char) return int with
     Convention    => C,
     External_Name => "wolfSSL_CTX_load_verify_locations",
     Import        => True;

   function Load_Verify_Locations3
     (Context : Context_Type;
      File    : access Interfaces.C.char;
      Path    : Byte_Array) return int with
     Convention    => C,
     External_Name => "wolfSSL_CTX_load_verify_locations",
     Import        => True;

   function Load_Verify_Locations4
     (Context : Context_Type;
      File    : access Interfaces.C.char;
      Path    : access Interfaces.C.char) return int with
     Convention    => C,
     External_Name => "wolfSSL_CTX_load_verify_locations",
     Import        => True;

   function Load_Verify_Locations (Context : Context_Type;
                                   File    : String;
                                   Path    : String)
                                   return Subprogram_Result is
   begin
      declare
         Ctx : constant Context_Type := Context;
         F : aliased Byte_Array := (1 .. File'Length + 1 => '#');
         P : aliased Byte_Array := (1 .. Path'Length + 1 => '#');
         Result : int;
      begin
         if File = "" then
            if Path = "" then
               Result := Load_Verify_Locations4 (Ctx, null, null);
            else
               for I in Path'Range loop
                  P (P'First + Byte_Index (I - Path'First)) :=
                    Byte_Type (Path (I));
               end loop;
               P (P'Last) := nul;
               Result := Load_Verify_Locations3 (Ctx, null, P);
            end if;
         else
            for I in File'Range loop
               F (F'First + Byte_Index (I - File'First)) :=
                 Byte_Type (File (I));
            end loop;
            F (F'Last) := nul;
            if Path = "" then
               Result := Load_Verify_Locations2 (Ctx, F, null);
            else
               for I in Path'Range loop
                  P (P'First + Byte_Index (I - Path'First)) :=
                    Byte_Type (Path (I));
               end loop;
               P (P'Last) := nul;
               Result := Load_Verify_Locations1 (Context => Ctx,
                                                 File    => F,
                                                 Path    => P);
            end if;
         end if;
         return Subprogram_Result (Result);
      end;
   exception
      when others =>
         return Exception_Error;
   end Load_Verify_Locations;

   function Load_Verify_Buffer
     (Context : Context_Type;
      Input   : Byte_Array;
      Size    : int;
      Format  : int) return int with
     Convention    => C,
     External_Name => "wolfSSL_CTX_load_verify_buffer",
     Import        => True;

   function Load_Verify_Buffer (Context : Context_Type;
                                Input   : Byte_Array;
                                Format  : File_Format)
                                return Subprogram_Result is
      Result : int;
   begin
      Result := Load_Verify_Buffer (Context => Context,
                                    Input   => Input,
                                    Size    => Input'Length,
                                    Format  => int(Format));
      return Subprogram_Result (Result);
   exception
      when others =>
         return Exception_Error;
   end Load_Verify_Buffer;

   function Is_Valid (Ssl : WolfSSL_Type) return Boolean is
   begin
      return Ssl /= null;
   end Is_Valid;

   function WolfSSL_New (Context : Context_Type)
                         return WolfSSL_Type with
     Convention    => C,
     External_Name => "wolfSSL_new",
     Import        => True;

   procedure Create_WolfSSL (Context : Context_Type;
                             Ssl     : out WolfSSL_Type) is
   begin
      Ssl := WolfSSL_New (Context);
   end Create_WolfSSL;

   function Use_Certificate_File (Ssl     : WolfSSL_Type;
                                  File    : Byte_Array;
                                  Format  : int)
                                  return int with
     Convention    => C,
     External_Name => "wolfSSL_use_certificate_file",
     Import        => True;

   function Use_Certificate_File (Ssl     : WolfSSL_Type;
                                  File    : String;
                                  Format  : File_Format)
                                  return Subprogram_Result is
   begin
      declare
         F : Byte_Array (1 .. File'Length + 1);
         Result : int;
      begin
         for I in File'Range loop
            F (F'First + Byte_Index (I - File'First)) :=
              Byte_Type (File (I));
         end loop;
         F (F'Last) := nul;
         Result := Use_Certificate_File (Ssl, F, int (Format));
         return Subprogram_Result (Result);
      end;
   exception
      when others =>
         return Exception_Error;
   end Use_Certificate_File;

   function Use_Certificate_Buffer (Ssl     : WolfSSL_Type;
                                    Input   : Byte_Array;
                                    Size    : long;
                                    Format  : int)
                                    return int with
     Convention    => C,
     External_Name => "wolfSSL_use_certificate_buffer",
     Import        => True;

   function Use_Certificate_Buffer (Ssl     : WolfSSL_Type;
                                    Input   : Byte_Array;
                                    Format  : File_Format)
                                    return Subprogram_Result is
      Result : int;
   begin
      Result := Use_Certificate_Buffer (Ssl, Input,
                                        Input'Length, int (Format));
      return Subprogram_Result (Result);
   exception
      when others =>
         return Exception_Error;
   end Use_Certificate_Buffer;

   function Use_Private_Key_File (Ssl     : WolfSSL_Type;
                                  File    : Byte_Array;
                                  Format  : int)
                                  return int with
     Convention    => C,
     External_Name => "wolfSSL_use_PrivateKey_file",
     Import        => True;

   function Use_Private_Key_File (Ssl     : WolfSSL_Type;
                                  File    : String;
                                  Format  : File_Format)
                                  return Subprogram_Result is
   begin
      declare
         F : Byte_Array (1 .. File'Length + 1);
         Result : int;
      begin
         for I in File'Range loop
            F (F'First + Byte_Index (I - File'First)) := Byte_Type (File (I));
         end loop;
         F (F'Last) := nul;
         Result := Use_Private_Key_File (Ssl, F, int (Format));
         return Subprogram_Result (Result);
      end;
   exception
      when others =>
         return Exception_Error;
   end Use_Private_Key_File;

   function Use_Private_Key_Buffer (Ssl     : WolfSSL_Type;
                                    Input   : Byte_Array;
                                    Size    : long;
                                    Format  : int)
                                    return int with
     Convention    => C,
     External_Name => "wolfSSL_use_PrivateKey_buffer",
     Import        => True;

   function Use_Private_Key_Buffer (Ssl     : WolfSSL_Type;
                                    Input   : Byte_Array;
                                    Format  : File_Format)
                                    return Subprogram_Result is
      Result : int;
   begin
      Result := Use_Private_Key_Buffer (Ssl, Input,
                                        Input'Length, int (Format));
      return Subprogram_Result (Result);
   exception
      when others =>
         return Exception_Error;
   end Use_Private_Key_Buffer;

   function WolfSSL_Set_Fd (Ssl : WolfSSL_Type; Fd : int) return int with
     Convention    => C,
     External_Name => "wolfSSL_set_fd",
     Import        => True;

   function Attach (Ssl    : WolfSSL_Type;
                    Socket : Integer)
                    return Subprogram_Result is
      Result : constant int := WolfSSL_Set_Fd (Ssl, int (Socket));
   begin
      return Subprogram_Result (Result);
   end Attach;

   procedure WolfSSL_Keep_Arrays (Ssl : WolfSSL_Type) with
     Convention    => C,
     External_Name => "wolfSSL_KeepArrays",
     Import        => True;

   procedure Keep_Arrays (Ssl : WolfSSL_Type) is
   begin
      WolfSSL_Keep_Arrays (Ssl);
   end Keep_Arrays;

   function WolfSSL_Accept (Ssl : WolfSSL_Type) return int with
     Convention    => C,
     External_Name => "wolfSSL_accept",
     Import        => True;

   function Accept_Connection (Ssl : WolfSSL_Type)
                               return Subprogram_Result is
      Result : constant int := WolfSSL_Accept (Ssl);
   begin
      return Subprogram_Result (Result);
   end Accept_Connection;

   procedure WolfSSL_Free_Arrays (Ssl : WolfSSL_Type) with
     Convention    => C,
     External_Name => "wolfSSL_FreeArrays",
     Import        => True;

   procedure Free_Arrays (Ssl : WolfSSL_Type) is
   begin
      WolfSSL_Free_Arrays (Ssl);
   end Free_Arrays;

   function WolfSSL_Read (Ssl  : WolfSSL_Type;
                          Data : out Byte_Array;
                          Sz   : int) return int with
     Convention    => C,
     External_Name => "wolfSSL_read",
     Import        => True;
   --  This function reads sz bytes from the SSL session (ssl) internal
   --  read buffer into the buffer data. The bytes read are removed from
   --  the internal receive buffer. If necessary wolfSSL_read() will
   --  negotiate an SSL/TLS session if the handshake has not already
   --  been performed yet by wolfSSL_connect() or wolfSSL_accept().
   --  The SSL/TLS protocol uses SSL records which have a maximum size
   --  of 16kB (the max record size can be controlled by the
   --  MAX_RECORD_SIZE define in /wolfssl/internal.h). As such, wolfSSL
   --  needs to read an entire SSL record internally before it is able
   --  to process and decrypt the record. Because of this, a call to
   --  wolfSSL_read() will only be able to return the maximum buffer
   --  size which has been decrypted at the time of calling. There may
   --  be additional not-yet-decrypted data waiting in the internal
   --  wolfSSL receive buffer which will be retrieved and decrypted with
   --  the next call to wolfSSL_read(). If sz is larger than the number
   --  of bytes in the internal read buffer, SSL_read() will return
   --  the bytes available in the internal read buffer. If no bytes are
   --  buffered in the internal read buffer yet, a call to wolfSSL_read()
   --  will trigger processing of the next record.
   --
   --  The integer returned is the number of bytes read upon success.
   --  0 will be returned upon failure. This may be caused by a either
   --  a clean (close notify alert) shutdown or just that the peer closed
   --  the connection. Call wolfSSL_get_error() for the specific
   --  error code. SSL_FATAL_ERROR will be returned upon failure when
   --  either an error occurred or, when using non-blocking sockets,
   --  the SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE error was received
   --  and and the application needs to call wolfSSL_read() again.
   --  Use wolfSSL_get_error() to get a specific error code.

   procedure Read (Ssl : WolfSSL_Type;
                   Result : out Read_Result) is
   begin
      Result := (Success => False,  --  In case of exception.
                 Last    => 0,
                 Code    => Subprogram_Result (Exception_Error));
      declare
         Data   : Byte_Array (1 .. Byte_Index'Last);
         Size   : int;
      begin
         Size := WolfSSL_Read (Ssl, Data, int (Byte_Index'Last));
         if Size <= 0 then
            Result := (Success => False,
                       Last    => 0,
                       Code    => Subprogram_Result (Size));
         else
            Result := (Success => True,
                       Last    => Byte_Index (Size),
                       Buffer  => Data (1 .. Byte_Index (Size)));
         end if;
      end;
   exception
      when others =>
         null;
   end Read;

   function WolfSSL_Write (Ssl  : WolfSSL_Type;
                           Data : Byte_Array;
                           Sz   : int) return int with
     Convention    => C,
     External_Name => "wolfSSL_write",
     Import        => True;

   procedure Write (Ssl  : WolfSSL_Type;
                    Data : Byte_Array;
                    Result : out Write_Result) is
   begin
      Result := (Success => False,
                 Code    => Subprogram_Result (Exception_Error));
      declare
         Size   : constant int := Data'Length;
         R : int;
      begin
         R := WolfSSL_Write (Ssl, Data, Size);
         if R > 0 then
            Result := (Success       => True,
                       Bytes_Written => Byte_Index (R));
         else
            Result := (Success => False, Code => Subprogram_Result (R));
         end if;
      end;
   exception
      when others =>
         null;
   end Write;

   function WolfSSL_Shutdown (Ssl : WolfSSL_Type) return int with
     Convention    => C,
     External_Name => "wolfSSL_shutdown",
     Import        => True;

   function Shutdown (Ssl : WolfSSL_Type) return Subprogram_Result is
      Result : constant int := WolfSSL_Shutdown (Ssl);
   begin
      return Subprogram_Result (Result);
   end Shutdown;

   function WolfSSL_Connect (Ssl : WolfSSL_Type) return int with
     Convention    => C,
     External_Name => "wolfSSL_connect",
     Import        => True;

   function Connect (Ssl : WolfSSL_Type) return Subprogram_Result is
      Result : constant int := WolfSSL_Connect (Ssl);
   begin
      return Subprogram_Result (Result);
   end Connect;

   procedure WolfSSL_Free (Ssl : WolfSSL_Type) with
     Convention    => C,
     External_Name => "wolfSSL_free",
     Import        => True;

   procedure Free (Ssl : in out WolfSSL_Type) is
   begin
      if Ssl /= null then
         WolfSSL_Free (Ssl);
      end if;
      Ssl := null;
   end Free;

   function WolfSSL_Get_Error (Ssl : WolfSSL_Type;
                               Ret : int) return int with
     Convention    => C,
     External_Name => "wolfSSL_get_error",
     Import        => True;

   function Get_Error (Ssl    : WolfSSL_Type;
                       Result : Subprogram_Result) return Error_Code is
   begin
      return Error_Code (WolfSSL_Get_Error (Ssl, int (Result)));
   end Get_Error;

   procedure WolfSSL_Error_String (Error : unsigned_long;
                                   Data  : out Byte_Array;
                                   Size  : unsigned_long) with
     Convention    => C,
     External_Name => "wolfSSL_ERR_error_string_n",
     Import        => True;

   procedure Error (Code    : in  Error_Code;
                    Message : in out Error_Message) is
      use type Byte_Type;
      -- Use unchecked conversion instead of type conversion to mimic C style
      -- conversion from int to unsigned long, avoiding the Ada overflow check.
      function To_Unsigned_Long is new Ada.Unchecked_Conversion
        (Source => long,
         Target => unsigned_long);
   begin
      declare
         S : String (1 .. Error_Message_Index'Last);
         B : Byte_Array (1 .. size_t (Error_Message_Index'Last));
         L : Positive;
      begin
         WolfSSL_Error_String (Error => To_Unsigned_Long (long (Code)),
                               Data  => B,
                               Size  => To_Unsigned_Long (long (B'Last)));
         for I in B'Range loop
            L := S'First + Natural (I - B'First);
            S (L) := Character (B (I));
            exit when B (I) = nul;
         end loop;
         if S (L) = Character (nul) then
            Message := (Last => L - 1,
                        Text => S (1 .. L - 1));
         else
            Message := (Last => L,
                        Text => S (1 .. L));
         end if;
      end;
   exception
      when others =>
         null;
   end Error;

   function Get_WolfSSL_Max_Error_Size return int with
     Convention    => C,
     External_Name => "get_wolfssl_max_error_size",
     Import        => True;

   function Max_Error_Size return Natural is
   begin
      return Natural (Get_WolfSSL_Max_Error_Size);
   end Max_Error_Size;

   function Is_Valid (Key : RNG_Type) return Boolean is
   begin
      return Key /= null;
   end Is_Valid;

   function Ada_New_RNG return RNG_Type with
     Convention    => C,
     External_Name => "ada_new_rng",
     Import        => True;

   procedure Ada_Free_RNG (Key : in RNG_Type) with
     Convention    => C,
     External_Name => "ada_free_rng",
     Import        => True;



   procedure Free_RNG (Key : in out RNG_Type) is
   begin
      if Key = null then
         return;
      end if;

      --  wc_rng_free() already calls wc_FreeRng() internally.
      Ada_Free_RNG (Key);

      --  Prevent accidental double-free and make Is_Valid return False.
      Key := null;
   end Free_RNG;

   procedure Create_RNG (Key    : in out RNG_Type;
                         Result : out Integer) is
   begin
      declare
         R : int;
      begin
         --  Allocate RNG using the C wrapper, which internally calls
         --  wc_rng_new(NULL, 0, NULL) as required.
         Key := Ada_New_RNG;

         if Key = null then
            Result := Exception_Error;
            return;
         end if;

         --  wc_rng_new() already calls wc_InitRng() internally, so no extra init.
         Result := 0;
      end;
   exception
      when others =>
         Result := Exception_Error;
   end Create_RNG;

   function WC_RNG_Generate_Block (RNG    : not null RNG_Type;
                                   Output : out Byte_Array;
                                   Size   : int) return int with
     Convention    => C,
     External_Name => "wc_RNG_GenerateBlock",
     Import        => True;

   procedure RNG_Generate_Block (RNG    : RNG_Type;
                                 Output : out Byte_Array;
                                 Result : out Integer) is
   begin
      declare
         R : int;
      begin
         R := WC_RNG_Generate_Block (RNG, Output, Output'Length);
         Result := Integer (R);
      end;
   exception
      when others =>
         Result := Exception_Error;
   end RNG_Generate_Block;

   type Unsigned_8 is mod 2 ** 8;

   function To_C (Value : Unsigned_8) return WolfSSL.Byte_Type is
   begin
      return WolfSSL.Byte_Type'Val (Value);
   end To_C;

   function WC_PBKDF2 (Output     : out Byte_Array;
                       Password   : Byte_Array;
                       P_Length   : int;
                       Salt       : Byte_Array;
                       S_Length   : int;
                       Iterations : int;
                       Key_Length : int;
                       Hash_Type  : int) return int with
     Convention    => C,
     External_Name => "wc_PBKDF2",
     Import        => True;

   function Ada_MD5 return int with
     Convention    => C,
     External_Name => "ada_md5",
     Import        => True;

   function Ada_SHA return int with
     Convention    => C,
     External_Name => "ada_sha",
     Import        => True;

   function Ada_SHA256 return int with
     Convention    => C,
     External_Name => "ada_sha256",
     Import        => True;

   function Ada_SHA384 return int with
     Convention    => C,
     External_Name => "ada_sha384",
     Import        => True;

   function Ada_SHA512 return int with
     Convention    => C,
     External_Name => "ada_sha512",
     Import        => True;

   function Ada_SHA3_224 return int with
     Convention    => C,
     External_Name => "ada_sha3_224",
     Import        => True;

   function Ada_SHA3_256 return int with
     Convention    => C,
     External_Name => "ada_sha3_256",
     Import        => True;

   function Ada_SHA3_384 return int with
     Convention    => C,
     External_Name => "ada_sha3_384",
     Import        => True;

   function Ada_SHA3_512 return int with
     Convention    => C,
     External_Name => "ada_sha3_512",
     Import        => True;

   procedure PBKDF2 (Output     : out Byte_Array;
                     Password   : Byte_Array;
                     Salt       : Byte_Array;
                     Iterations : Positive;
                     Key_Length : Positive;
                     HMAC       : HMAC_Hash;
                     Result     : out Integer) is
   begin
      declare
         R : int;
         H : int;
      begin
         case HMAC is
            when MD5      => H := Ada_MD5;
            when SHA      => H := Ada_SHA;
            when SHA256   => H := Ada_SHA256;
            when SHA384   => H := Ada_SHA384;
            when SHA512   => H := Ada_SHA512;
            when SHA3_224 => H := Ada_SHA3_224;
            when SHA3_256 => H := Ada_SHA3_256;
            when SHA3_384 => H := Ada_SHA3_384;
            when SHA3_512 => H := Ada_SHA3_512;
         end case;
         R := WC_PBKDF2 (Output     => Output,
                         Password   => Password,
                         P_Length   => Password'Length,
                         Salt       => Salt,
                         S_Length   => Salt'Length,
                         Iterations => int (Iterations),
                         Key_Length => int (Key_Length),
                         Hash_Type  => H);
         Result := Integer (R);
      end;
   exception
      when others =>
         Result := Exception_Error;
   end PBKDF2;

   function Ada_RSA_Set_RNG (Key : not null RSA_Key_Type;
                             RNG : not null RNG_Type) return int with
     Convention    => C,
     External_Name => "ada_RsaSetRNG",
     Import        => True;

   procedure Rsa_Set_RNG (Key    : in out Rsa_Key_Type;
                          RNG    : in out RNG_Type;
                          Result : out Integer) is
   begin
      declare
         R : int;
      begin
         R := Ada_RSA_Set_RNG (Key, RNG);
         Result := Integer (R);
      end;
   exception
      when others =>
         Result := Exception_Error;
   end Rsa_Set_RNG;

   function Is_Valid (Key : RSA_Key_Type) return Boolean is
   begin
      return Key /= null;
   end Is_Valid;

   function Ada_New_RSA return RSA_Key_Type with
     Convention    => C,
     External_Name => "ada_new_rsa",
     Import        => True;

   procedure Ada_Free_RSA (Key : in RSA_Key_Type) with
     Convention    => C,
     External_Name => "ada_free_rsa",
     Import        => True;

   procedure Free_RSA (Key : in out RSA_Key_Type) is
   begin
      if Key = null then
         return;
      end if;

      --  wc_DeleteRsaKey() already calls wc_FreeRsaKey() internally.
      Ada_Free_RSA (Key);

      --  Prevent accidental double-free and make Is_Valid return False.
      Key := null;
   end Free_RSA;

   procedure Create_RSA (Key    : in out RSA_Key_Type;
                         Result : out Integer) is
   begin
      --  Allocate and initialize RSA key using the C wrapper.
      --  The wrapper uses wc_NewRsaKey() and returns NULL on failure.
      Key := Ada_New_RSA;

      if Key = null then
         Result := Exception_Error;
         return;
      end if;

      --  wc_NewRsaKey() already calls wc_InitRsaKey_ex() internally.
      Result := 0;

   exception
      when others =>
         --  Avoid leaking the dynamically allocated RSA key on failure.
         if Key /= null then
            Ada_Free_RSA (Key);
            Key := null;
         end if;
         Result := Exception_Error;
   end Create_RSA;

   function RSA_Public_Key_Decode (Input : Byte_Array;
                                   Index : in out int;
                                   Key   : not null RSA_Key_Type;
                                   Size  : int) return int with
     Convention    => C,
     External_Name => "wc_RsaPublicKeyDecode",
     Import        => True;

   procedure Rsa_Public_Key_Decode (Input : Byte_Array;
                                    Index : in out Byte_Index;
                                    Key   : in out RSA_Key_Type;
                                    Size  : Integer;
                                    Result : out Integer) is
   begin
      declare
         I : aliased int := int (Index);
         R : constant int :=
           RSA_Public_Key_Decode (Input, I, Key, int (Size));
      begin
         Index := WolfSSL.Byte_Index (I);
         Result := Integer (R);
      end;
   exception
      when others =>
         Result := Exception_Error;
   end Rsa_Public_Key_Decode;

   function RSA_Private_Key_Decode (Input : Byte_Array;
                                    Index : in out int;
                                    Key   : not null RSA_Key_Type;
                                    Size  : int) return int with
     Convention    => C,
     External_Name => "wc_RsaPrivateKeyDecode",
     Import        => True;

   procedure Rsa_Private_Key_Decode (Input : Byte_Array;
                                     Index : in out Byte_Index;
                                     Key   : in out RSA_Key_Type;
                                     Size  : Integer;
                                     Result : out Integer) is
   begin
      declare
         I : aliased int := int (Index);
         R : constant int :=
           RSA_Private_Key_Decode (Input, I, Key, int (Size));
      begin
         Index := WolfSSL.Byte_Index (I);
         Result := Integer (R);
      end;
   exception
      when others =>
         Result := Exception_Error;
   end Rsa_Private_Key_Decode;

   function RSA_SSL_Sign (Input      : Byte_Array;
                          In_Length  : int;
                          Output     : in out Byte_Array;
                          Out_Length : int;
                          RSA        : not null RSA_Key_Type;
                          RNG        : not null RNG_Type)
                          return int with
     Convention    => C,
     External_Name => "wc_RsaSSL_Sign",
     Import        => True;

   procedure Rsa_SSL_Sign (Input  : Byte_Array;
                           Output : in out Byte_Array;
                           RSA    : in out RSA_Key_Type;
                           RNG    : in out RNG_Type;
                           Result : out Integer) is
   begin
      declare
         R : constant int :=
           RSA_SSL_Sign (Input,
                         Input'Length,
                         Output,
                         Output'Length,
                         RSA,
                         RNG);
      begin
         Result := Integer (R);
      end;
   exception
      when others =>
         Result := Exception_Error;
   end Rsa_SSL_Sign;

   function WC_RSA_SSL_Verify (Input      : Byte_Array;
                               In_Length  : int;
                               Output     : in out Byte_Array;
                               Out_Length : int;
                               RSA        : not null RSA_Key_Type)
                               return int with
     Convention    => C,
     External_Name => "wc_RsaSSL_Verify",
     Import        => True;

   procedure Rsa_SSL_Verify (Input  : Byte_Array;
                             Output : in out Byte_Array;
                             RSA    : in out RSA_Key_Type;
                             Result : out Integer) is
   begin
      declare
         R : constant int :=
           WC_RSA_SSL_Verify (Input,
                              Input'Length,
                              Output,
                              Output'Length,
                              RSA);
      begin
         Result := Integer (R);
      end;
   exception
      when others =>
         Result := Exception_Error;
   end Rsa_SSL_Verify;

   function WC_RSA_Public_Encrypt (Input      : Byte_Array;
                                   In_Length  : int;
                                   Output     : in out Byte_Array;
                                   Out_Length : int;
                                   RSA        : not null RSA_Key_Type;
                                   RNG        : not null RNG_Type)
                                   return int with
     Convention    => C,
     External_Name => "wc_RsaPublicEncrypt",
     Import        => True;

   procedure RSA_Public_Encrypt (Input  : Byte_Array;
                                 Output : in out Byte_Array;
                                 Index  :    out Byte_Index;
                                 RSA    : in out RSA_Key_Type;
                                 RNG    : in out RNG_Type;
                                 Result : out Integer) is
   begin
      Index := 0;
      declare
         R : constant int :=
           WC_RSA_Public_Encrypt (Input,
                                  Input'Length,
                                  Output,
                                  Output'Length,
                                  RSA,
                                  RNG);
      begin
         Result := Integer (R);
         if Result >= 0 then
            Index := Byte_Index (Result);
         end if;
      end;
   exception
      when others =>
         Result := Exception_Error;
   end RSA_Public_Encrypt;

   function WC_RSA_Private_Decrypt (Input      : Byte_Array;
                                    In_Length  : int;
                                    Output     : in out Byte_Array;
                                    Out_Length : int;
                                    RSA        : not null RSA_Key_Type)
                                    return int with
     Convention    => C,
     External_Name => "wc_RsaPrivateDecrypt",
     Import        => True;

   procedure RSA_Private_Decrypt (Input  : Byte_Array;
                                  Output : in out Byte_Array;
                                  Index  :    out Byte_Index;
                                  RSA    : in out RSA_Key_Type;
                                  Result :    out Integer) is
   begin
      Index := 0;
      declare
         R : constant int :=
           WC_RSA_Private_Decrypt (Input,
                                   Input'Length,
                                   Output,
                                   Output'Length,
                                   RSA);
      begin
         Result := Integer (R);
         if Result >= 0 then
            Index := Byte_Index (Result);
         end if;
      end;
   exception
      when others =>
         Result := Exception_Error;
   end RSA_Private_Decrypt;

   function Init_SHA256 (SHA256 : not null Sha256_Type) return int with
     Convention    => C,
     External_Name => "wc_InitSha256",
     Import        => True;

   function SHA256_Update (SHA256 : not null Sha256_Type;
                           Byte   : Byte_Array;
                           Length : int) return int with
     Convention    => C,
     External_Name => "wc_Sha256Update",
     Import        => True;

   function SHA256_Final (SHA256 : not null Sha256_Type;
                          Hash   : out Byte_Array) return int with
     Convention    => C,
     External_Name => "wc_Sha256Final",
     Import        => True;

   function Is_Valid (SHA256 : SHA256_Type) return Boolean is
   begin
      return SHA256 /= null;
   end Is_Valid;

   function Ada_New_SHA256 return SHA256_Type with
     Convention    => C,
     External_Name => "ada_new_sha256",
     Import        => True;

   procedure Ada_Free_SHA256 (SHA256 : in SHA256_Type) with
     Convention    => C,
     External_Name => "ada_free_sha256",
     Import        => True;

   procedure Free_SHA256 (SHA256 : in out SHA256_Type) is
      --  Ensure any internal wolfCrypt resources are released (hardware locks,
      --  etc.) before releasing the object storage itself.
      procedure WC_Sha256_Free (SHA256 : not null SHA256_Type) with
        Convention    => C,
        External_Name => "wc_Sha256Free",
        Import        => True;
   begin
      if SHA256 = null then
         return;
      end if;

      WC_Sha256_Free (SHA256);
      Ada_Free_SHA256 (SHA256);

      --  Prevent accidental double-free and make Is_Valid return False.
      SHA256 := null;
   end Free_SHA256;

   procedure Create_SHA256 (SHA256 : in out SHA256_Type;
                            Result : out Integer) is
   begin
      declare
         R : int;
      begin
         SHA256 := Ada_New_SHA256;

         if SHA256 = null then
            Result := Exception_Error;
            return;
         end if;

         R := Init_SHA256 (SHA256);
         Result := Integer (R);

         if Result /= 0 then
            --  Avoid leaking the dynamically allocated SHA256 on init failure.
            --  Also clear the handle to prevent accidental double-free by caller.
            Ada_Free_SHA256 (SHA256);
            SHA256 := null;
         end if;
      end;
   exception
      when others =>
         Result := Exception_Error;
   end Create_SHA256;

   procedure Update_SHA256 (SHA256 : in out SHA256_Type;
                            Byte   : Byte_Array;
                            Result : out Integer) is
   begin
      declare
         R : int;
      begin
         R := SHA256_Update (SHA256, Byte, Byte'Length);
         Result := Integer (R);
      end;
   exception
      when others =>
         Result := Exception_Error;
   end Update_SHA256;

   procedure Finalize_SHA256 (SHA256 : in out SHA256_Type;
                              Hash   : out SHA256_Hash;
                              Result : out Integer) is
      R : int;
   begin
      R := SHA256_Final (SHA256, Hash);
      Result := Integer (R);
   exception
      when others =>
         Result := Exception_Error;
   end Finalize_SHA256;

   function WC_Get_Invalid_Device_Identifier return int with
     Convention    => C,
     External_Name => "get_wolfssl_invalid_devid",
     Import        => True;

   function Invalid_Device return Device_Identifier is
   begin
      return Device_Identifier (WC_Get_Invalid_Device_Identifier);
   end Invalid_Device;

   function Is_Valid (AES : AES_Type) return Boolean is
   begin
      return AES /= null;
   end Is_Valid;

   function Ada_New_AES (Device : int)
                         return AES_Type with
     Convention    => C,
     External_Name => "ada_new_aes",
     Import        => True;

   procedure Ada_Free_AES (AES : in AES_Type) with
     Convention    => C,
     External_Name => "ada_free_aes",
     Import        => True;

   procedure Create_AES (Device : Device_Identifier;
                         AES    : in out AES_Type;
                         Result : out Integer) is
   begin
      declare
         R : int;
      begin
         --  Allocate and initialize AES using the C wrapper.
         --  The wrapper is expected to call wc_AesNew(NULL, devId, &ret) and
         --  return NULL on failure.
         AES := Ada_New_AES (int (Device));

         if AES = null then
            Result := Exception_Error;
            return;
         end if;

         --  wc_AesNew() already calls wc_AesInit() internally, so no extra init.
         Result := 0;
      end;
   exception
      when others =>
         --  Avoid leaking the dynamically allocated AES on failure.
         if AES /= null then
            Ada_Free_AES (AES);
            AES := null;
         end if;
         Result := Exception_Error;
   end Create_AES;

   function AES_Set_Key (AES : not null AES_Type;
                         Key : Byte_Array;
                         Length : int;
                         IV : Byte_Array;
                         Dir : int) return int with
     Convention    => C,
     External_Name => "wc_AesSetKey",
     Import        => True;

   procedure AES_Set_Key (AES    : AES_Type;
                          Key    : Byte_Array;
                          Length : Integer;
                          IV     : Byte_Array;
                          Dir    : Integer;
                          Result : out Integer) is
   begin
      declare
         R : int;
      begin
         R := AES_Set_Key (AES, Key, int (Length), IV, int (Dir));
         Result := Integer (R);
      end;
   exception
      when others =>
         Result := Exception_Error;
   end AES_Set_Key;

   function AES_Set_IV (AES : not null AES_Type;
                        IV : Byte_Array) return int with
     Convention    => C,
     External_Name => "wc_AesSetIV",
     Import        => True;

   procedure AES_Set_IV (AES : AES_Type;
                         IV  : Byte_Array;
                         Result : out Integer) is
   begin
      declare
         R : int;
      begin
         R := AES_Set_IV (AES, IV);
         Result := Integer (R);
      end;
   exception
      when others =>
         Result := Exception_Error;
   end AES_Set_IV;

   function AES_Set_Cbc_Encrypt (AES : not null AES_Type;
                                 Output : out Byte_Array;
                                 Input : Byte_Array;
                                 Size : int) return int with
     Convention    => C,
     External_Name => "wc_AesCbcEncrypt",
     Import        => True;

   procedure AES_Set_Cbc_Encrypt (AES : AES_Type;
                                  Output : out Byte_Array;
                                  Input : Byte_Array;
                                  Size : Integer;
                                  Result : out Integer) is
   begin
      declare
         R : int;
      begin
         R := AES_Set_Cbc_Encrypt (AES, Output, Input, int (Size));
         Result := Integer (R);
      end;
   exception
      when others =>
         Result := Exception_Error;
   end AES_Set_Cbc_Encrypt;

   function AES_Set_Cbc_Decrypt (AES : not null AES_Type;
                                 Output : out Byte_Array;
                                 Input : Byte_Array;
                                 Size : int) return int with
     Convention    => C,
     External_Name => "wc_AesCbcDecrypt",
     Import        => True;

   procedure AES_Set_Cbc_Decrypt (AES : AES_Type;
                                  Output : out Byte_Array;
                                  Input : Byte_Array;
                                  Size : Integer;
                                  Result : out Integer) is
   begin
      declare
         R : int;
      begin
         R := AES_Set_Cbc_Decrypt (AES, Output, Input, int (Size));
         Result := Integer (R);
      end;
   exception
      when others =>
         Result := Exception_Error;
   end AES_Set_Cbc_Decrypt;

   procedure AES_Free (AES : in out AES_Type;
                       Result : out Integer) is
   begin
      if AES = null then
         Result := Exception_Error;
         return;
      end if;

      --  wc_AesDelete() already calls wc_AesFree() internally.
      Ada_Free_AES (AES);
      AES := null;
      Result := 0;
   exception
      when others =>
         Result := Exception_Error;
   end AES_Free;

begin
   null;
end WolfSSL;
