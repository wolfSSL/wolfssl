-- tls_client.adb
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

--  Ada Standard Library packages.
with Ada.Characters.Handling;
with Ada.Command_Line;
with Ada.Strings.Bounded;
with Ada.Text_IO.Bounded_IO;
with Interfaces.C;

--  GNAT Library packages.
with GNAT.Sockets;

--  The WolfSSL package.
with WolfSSL;

package body Tls_Client is

   use type WolfSSL.Mode_Type;
   use type WolfSSL.Byte_Index;
   use type WolfSSL.Byte_Array;

   use all type WolfSSL.Subprogram_Result;

   subtype Byte_Type is WolfSSL.Byte_Type;

   package Messages is new Ada.Strings.Bounded.Generic_Bounded_Length (Max => 200);
   use all type Messages.Bounded_String;

   package Integer_IO is new Ada.Text_IO.Integer_IO (Integer);

   package Messages_IO is new Ada.Text_IO.Bounded_IO (Messages);

   procedure Put (Text : String) is
   begin
      Ada.Text_IO.Put (Text);
   end Put;

   procedure Put (Number : Integer) is
   begin
      Integer_IO.Put (Item => Number, Width => 0, Base => 10);
   end Put;

   procedure Put_Line (Text : String) is
   begin
      Ada.Text_IO.Put_Line (Text);
   end Put_Line;

   procedure New_Line is
   begin
      Ada.Text_IO.New_Line;
   end New_Line;

   procedure Put_Line (Text : Messages.Bounded_String) is
   begin
      Messages_IO.Put_Line (Text);
   end Put_Line;

   subtype Exit_Status is Ada.Command_Line.Exit_Status;

   Exit_Status_Success : Exit_Status renames Ada.Command_Line.Success;
   Exit_Status_Failure : Exit_Status renames Ada.Command_Line.Failure;

   procedure Set (Status : Exit_Status) is
   begin
      Ada.Command_Line.Set_Exit_Status (Status);
   end Set;

   subtype Port_Type is GNAT.Sockets.Port_Type;

   subtype Level_Type is GNAT.Sockets.Level_Type;

   subtype Socket_Type is GNAT.Sockets.Socket_Type;
   subtype Option_Name is GNAT.Sockets.Option_Name;
   subtype Option_Type is GNAT.Sockets.Option_Type;
   subtype Family_Type is GNAT.Sockets.Family_Type;

   subtype Sock_Addr_Type is GNAT.Sockets.Sock_Addr_Type;
   subtype Inet_Addr_Type is GNAT.Sockets.Inet_Addr_Type;

   Socket_Error : exception renames GNAT.Sockets.Socket_Error;

   Reuse_Address : Option_Name renames GNAT.Sockets.Reuse_Address;

   Socket_Level : Level_Type renames GNAT.Sockets.Socket_Level;

   Family_Inet : Family_Type renames GNAT.Sockets.Family_Inet;

   Any_Inet_Addr : Inet_Addr_Type renames GNAT.Sockets.Any_Inet_Addr;

   CERT_FILE : constant String := "../certs/client-cert.pem";
   KEY_FILE  : constant String := "../certs/client-key.pem";
   CA_FILE   : constant String := "../certs/ca-cert.pem";

   subtype Byte_Array is WolfSSL.Byte_Array;

   function Argument_Count return Natural is
   begin
      return Ada.Command_Line.Argument_Count;
   end Argument_Count;

   function Argument (Number : Positive) return String is
   begin
      return Ada.Command_Line.Argument (Number);
   end Argument;

   procedure Run is
      A : Sock_Addr_Type;
      C : Socket_Type;  --  Client socket.
      D : Byte_Array (1 .. 200);
      P : constant Port_Type := 11111;

      Ssl : WolfSSL.WolfSSL_Type;
      Ctx : WolfSSL.Context_Type;

      Bytes_Written : Integer;

      Count : WolfSSL.Byte_Index;

      Text : String (1 .. 200);
      Last : Integer;

      Input : WolfSSL.Read_Result;

      Result : WolfSSL.Subprogram_Result;
   begin
      if Argument_Count /= 1 then
         Put_Line ("usage: tcl_client <IPv4 address>");
         return;
      end if;
      GNAT.Sockets.Create_Socket (Socket => C);

      A := (Family => Family_Inet,
            Addr   => GNAT.Sockets.Inet_Addr (Argument (1)),
            Port   => P);

      GNAT.Sockets.Connect_Socket (Socket => C,
                                   Server => A);

      --  Create and initialize WOLFSSL_CTX.
      WolfSSL.Create_Context (Method  => WolfSSL.TLSv1_3_Client_Method,
                              Context => Ctx);
      if not WolfSSL.Is_Valid (Ctx) then
         Put_Line ("ERROR: failed to create WOLFSSL_CTX.");
         Set (Exit_Status_Failure);
         return;
      end if;

      --  Load client certificate into WOLFSSL_CTX.
      Result := WolfSSL.Use_Certificate_File (Context => Ctx,
                                              File    => CERT_FILE,
                                              Format  => WolfSSL.Format_Pem);
      if Result = Failure then
         Put ("ERROR: failed to load ");
         Put (CERT_FILE);
         Put (", please check the file.");
         New_Line;
         Set (Exit_Status_Failure);
         return;
      end if;

      --  Load client key into WOLFSSL_CTX.
      Result := WolfSSL.Use_Private_Key_File (Context => Ctx,
                                              File    => KEY_FILE,
                                              Format  => WolfSSL.Format_Pem);
      if Result = Failure then
         Put ("ERROR: failed to load ");
         Put (KEY_FILE);
         Put (", please check the file.");
         New_Line;
         Set (Exit_Status_Failure);
         return;
      end if;

      --  Load CA certificate into WOLFSSL_CTX.
      Result := WolfSSL.Load_Verify_Locations (Context => Ctx,
                                               File    => CA_FILE,
                                               Path    => "");
      if Result = Failure then
         Put ("ERROR: failed to load ");
         Put (CA_FILE);
         Put (", please check the file.");
         New_Line;
         Set (Exit_Status_Failure);
         return;
      end if;

      --  Create a WOLFSSL object.
      WolfSSL.Create_WolfSSL (Context => Ctx, Ssl => Ssl);
      if not WolfSSL.Is_Valid (Ssl) then
         Put_Line ("ERROR: failed to create WOLFSSL object.");
         Set (Exit_Status_Failure);
         return;
      end if;

      --  Attach wolfSSL to the socket.
      Result := WolfSSL.Attach (Ssl    => Ssl,
                                Socket => GNAT.Sockets.To_C (C));
      if Result = Failure then
         Put_Line ("ERROR: Failed to set the file descriptor.");
         Set (Exit_Status_Failure);
         return;
      end if;

      Result := WolfSSL.Connect (Ssl);
      if Result = Failure then
         Put_Line ("ERROR: failed to connect to wolfSSL.");
         Set (Exit_Status_Failure);
         return;
      end if;

      Put ("Message for server: ");
      Ada.Text_IO.Get_Line (Text, Last);

      Interfaces.C.To_C (Item       => Text (1 .. Last),
                         Target     => D,
                         Count      => Count,
                         Append_Nul => False);
      Bytes_Written := WolfSSL.Write (Ssl  => Ssl,
                                      Data => D (1 .. Count));
      if Bytes_Written < Last then
         Put ("ERROR: failed to write entire message");
         New_Line;
         Put (Bytes_Written);
         Put (" bytes of ");
         Put (Last);
         Put ("bytes were sent");
         New_Line;
         return;
      end if;

      Input := WolfSSL.Read (Ssl);
      if Input.Result /= Success then
         Put_Line ("Read error.");
         Set (Exit_Status_Failure);
         return;
      end if;
      Interfaces.C.To_Ada (Item     => Input.Buffer,
                           Target   => Text,
                           Count    => Last,
                           Trim_Nul => False);
      Put ("Server: ");
      Put (Text (1 .. Last));
      New_Line;

      GNAT.Sockets.Close_Socket (C);
      WolfSSL.Free (Ssl);
      WolfSSL.Free (Context => Ctx);
   end Run;

end Tls_Client;
