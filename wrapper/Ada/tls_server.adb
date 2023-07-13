-- tls_server.adb
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

--  GNAT Library packages.
with GNAT.Sockets;

--  The WolfSSL package.
with WolfSSL;

package body Tls_Server is

   use type WolfSSL.Mode_Type;
   use type WolfSSL.Byte_Index;
   use type WolfSSL.Byte_Array;

   use all type WolfSSL.Subprogram_Result;

   package Messages is new Ada.Strings.Bounded.Generic_Bounded_Length (Max => 200);
   use all type Messages.Bounded_String;

   package Messages_IO is new Ada.Text_IO.Bounded_IO (Messages);

   procedure Put_Line (Text : String) is
   begin
      Ada.Text_IO.Put_Line (Text);
   end Put_Line;

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

   CERT_FILE : constant String := "../certs/server-cert.pem";
   KEY_FILE  : constant String := "../certs/server-key.pem";
   CA_FILE   : constant String := "../certs/client-cert.pem";

   subtype Byte_Array is WolfSSL.Byte_Array;

   Reply : constant Byte_Array := "I hear ya fa shizzle!";

   procedure Run is
      A : Sock_Addr_Type;
      L : Socket_Type;  --  Listener socket.
      C : Socket_Type;  --  Client socket.
      P : constant Port_Type := 11111;

      Ch : Character;

      Ssl : WolfSSL.WolfSSL_Type;

      Ctx : WolfSSL.Context_Type;
      Result : WolfSSL.Subprogram_Result;
      M : Messages.Bounded_String;
      Shall_Continue : Boolean := True;

      Bytes_Written : Integer;

      Input : WolfSSL.Read_Result;
   begin
      GNAT.Sockets.Create_Socket (Socket => L);
      GNAT.Sockets.Set_Socket_Option (Socket => L,
                                      Level  => Socket_Level,
                                      Option => (Name    => Reuse_Address,
                                                 Enabled => True));
      GNAT.Sockets.Bind_Socket (Socket  => L,
                                Address => (Family => Family_Inet,
                                            Addr   => Any_Inet_Addr,
                                            Port   => P));
      GNAT.Sockets.Listen_Socket (Socket => L,
                                  Length => 5);

      --  Create and initialize WOLFSSL_CTX.
      WolfSSL.Create_Context (Method  => WolfSSL.TLSv1_3_Server_Method,
                              Context => Ctx);
      if not WolfSSL.Is_Valid (Ctx) then
         Put_Line ("ERROR: failed to create WOLFSSL_CTX.");
         Set (Exit_Status_Failure);
         return;
      end if;

      --  Require mutual authentication.
      WolfSSL.Set_Verify
         (Context => Ctx,
          Mode    => WolfSSL.Verify_Peer & WolfSSL.Verify_Fail_If_No_Peer_Cert);

      --  Load server certificates into WOLFSSL_CTX.
      Result := WolfSSL.Use_Certificate_File (Context => Ctx,
                                              File    => CERT_FILE,
                                              Format  => WolfSSL.Format_Pem);
      if Result = Failure then
         M := Messages.To_Bounded_String ("ERROR: failed to load ");
         Messages.Append (M, CERT_FILE);
         Messages.Append (M, ", please check the file.");
         Put_Line (M);
         Set (Exit_Status_Failure);
         return;
      end if;

      --  Load server key into WOLFSSL_CTX.
      Result := WolfSSL.Use_Private_Key_File (Context => Ctx,
                                              File    => KEY_FILE,
                                              Format  => WolfSSL.Format_Pem);
      if Result = Failure then
         M := Messages.To_Bounded_String ("ERROR: failed to load ");
         Messages.Append (M, KEY_FILE);
         Messages.Append (M, ", please check the file.");
         Put_Line (M);
         Set (Exit_Status_Failure);
         return;
      end if;

      --  Load client certificate as "trusted" into WOLFSSL_CTX.
      Result := WolfSSL.Load_Verify_Locations (Context => Ctx,
                                               File    => CA_FILE,
                                               Path    => "");
      if Result = Failure then
         M := Messages.To_Bounded_String ("ERROR: failed to load ");
         Messages.Append (M, CA_FILE);
         Messages.Append (M, ", please check the file.");
         Put_Line (M);
         Set (Exit_Status_Failure);
         return;
      end if;

      while Shall_Continue loop
         Put_Line ("Waiting for a connection...");
         begin
            GNAT.Sockets.Accept_Socket (Server  => L,
                                        Socket  => C,
                                        Address => A);
         exception
            when Socket_Error =>
               Shall_Continue := False;
               Put_Line ("ERROR: failed to accept the connection.");
         end;

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

         --  Establish TLS connection.
         Result := WolfSSL.Accept_Connection (Ssl);
         if Result = Failure then
            Put_Line ("Accept error.");
            Set (Exit_Status_Failure);
            return;
         end if;

         Put_Line ("Client connected successfully.");

         Input := WolfSSL.Read (Ssl);

         if Input.Result /= Success then
            Put_Line ("Read error.");
            Set (Exit_Status_Failure);
            return;
         end if;

         --  Print to stdout any data the client sends.
         M := Messages.To_Bounded_String ("");
         for I in Input.Buffer'Range loop
            Ch := Character (Input.Buffer (I));
            if Ada.Characters.Handling.Is_Graphic (Ch) then
               Messages.Append (M, Ch);
            else
               null;
               --  Ignore the "newline" characters at end of message.
            end if;
         end loop;
         Put_Line (M);

         --  Check for server shutdown command.
         if Input.Last >= 8  then
            if Input.Buffer (1 .. 8) = "shutdown" then
               Put_Line ("Shutdown command issued!");
               Shall_Continue := False;
            end if;
         end if;

         Bytes_Written := WolfSSL.Write (Ssl, Reply);
         if Bytes_Written /= Reply'Length then
            Put_Line ("ERROR: failed to write.");
         end if;

         Result := WolfSSL.Shutdown (Ssl);
         WolfSSL.Free (Ssl);
         GNAT.Sockets.Close_Socket (C);

         Put_Line ("Shutdown complete.");
      end loop;
      GNAT.Sockets.Close_Socket (L);
      WolfSSL.Free (Context => Ctx);
      WolfSSL.Finalize;
   end Run;

end Tls_Server;
