with Interfaces.C;

--  This package is annotated "with SPARK_Mode" that SPARK can verify
--  the API of this package is used correctly. The body of this package
--  cannot be formally verified since it calls C functions and uses
--  access-to-object types which are not part of the SPARK subset of
--  the Ada programming language.
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

   subtype Byte_Index is Interfaces.C.size_t range 0 .. 16_000;
   subtype Byte_Array is Interfaces.C.char_array;

   type Subprogram_Result is (Success, Failure);

   type Context_Type is limited private;

   type Optional_Context (Exists : Boolean := False) is record
      case Exists is
         when True  => Instance : Context_Type;
         when False => null;
      end case;
   end record;

   type Method_Type is limited private;

   function TLSv1_2_Server_Method return Method_Type;
   function TLSv1_3_Server_Method return Method_Type;

   procedure Create_Context (Method  : Method_Type;
                             Context : out Optional_Context);
   --  Create and initialize a WolfSSL context.

   procedure Free (Context : in out Optional_Context) with
      Pre  => Context.Exists,
      Post => not Context.Exists;

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
                         Mode    : Mode_Type);

   type File_Format is private;

   Format_Asn1    : constant File_Format;
   Format_Pem     : constant File_Format;
   Format_Default : constant File_Format;

   function Use_Certificate_File (Context : Context_Type;
                                  File    : String;
                                  Format  : File_Format)
                                  return Subprogram_Result;

   function Use_Certificate_Buffer (Context : Context_Type;
                                    Input   : char_array;
                                    Format  : File_Format)
                                    return Subprogram_Result;

   function Use_Private_Key_File (Context : Context_Type;
                                  File    : String;
                                  Format  : File_Format)
                                  return Subprogram_Result;

   function Use_Private_Key_Buffer (Context : Context_Type;
                                    Input   : Byte_Array;
                                    Format  : File_Format)
                                    return Subprogram_Result;

   function Load_Verify_Locations (Context : Context_Type;
                                   File    : String;
                                   Path    : String)
                                   return Subprogram_Result;

   function Load_Verify_Buffer (Context : Context_Type;
                                Input   : Byte_Array;
                                Format  : File_Format)
                                return Subprogram_Result;

   type WolfSSL_Type is limited private;

   type Optional_WolfSSL (Exists : Boolean := False) is record
      case Exists is
         when True  => Instance : WolfSSL_Type;
         when False => null;
      end case;
   end record;

   procedure Create_WolfSSL (Context : Context_Type;
                             Ssl     : out Optional_WolfSSL);

   --  Attach wolfSSL to the socket.
   function Attach (Ssl    : WolfSSL_Type;
                    Socket : Integer)
                    return Subprogram_Result;

   procedure Keep_Arrays (Ssl : WolfSSL_Type);
   --  Don't free temporary arrays at end of handshake.

   procedure Free_Arrays (Ssl : WolfSSL_Type);
   --  User doesn't need temporary arrays anymore, Free.

   function Accept_Connection (Ssl : WolfSSL_Type)
                               return Subprogram_Result;

   --  This record type has discriminants with default values to be able
   --  to compile this code under the restriction no secondary stack.
   type Read_Result (Result : Subprogram_Result := Failure;
                     Last   : Byte_Index := Byte_Index'Last) is record
      case Result is
         when Success => Buffer : Byte_Array (1 .. Last);
         when Failure => null;
      end case;
   end record;

   function Read (Ssl : WolfSSL_Type) return Read_Result;

   --  The number of bytes written is returned.
   function Write (Ssl  : WolfSSL_Type; Data : Byte_Array) return Integer;

   function Shutdown (Ssl : WolfSSL_Type) return Subprogram_Result;

   procedure Free (Ssl : in out Optional_WolfSSL) with
      Pre  => Ssl.Exists,
      Post => not Ssl.Exists;

   function Connect (Ssl : WolfSSL_Type) return Subprogram_Result;

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
