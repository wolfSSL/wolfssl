--  Ada Standard Library packages.
with Ada.Characters.Handling;
with Ada.Command_Line;
with Ada.Strings.Bounded;
with Ada.Text_IO.Bounded_IO;

--  GNAT Library packages.
with GNAT.Sockets;

--  The WolfSSL package.
with WolfSSL;

package body Tls_Client is

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

   procedure Run is
      A : Sock_Addr_Type;
      C : Socket_Type;  --  Client socket.
   begin
      null; -- work in progress.
   end Run;

end Tls_Client;
