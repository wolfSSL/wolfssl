with GNAT.Sockets;
with Interfaces.C.Strings;

--  This package contains the subprograms that need the Ada run-time
--  to support the Interfaces.C.Strings and GNAT.Sockets packages.
--  An example of an Ada run-time that does not support this package
--  is the Zero Footprint run-time of the GNAT compiler.
package WolfSSL.Full_Runtime with SPARK_Mode is

   function DTLS_Set_Peer
     (Ssl     : WolfSSL_Type;
      Address : GNAT.Sockets.Sock_Addr_Type)
      return Subprogram_Result with
     Pre => Is_Valid (Ssl);
   --  This function wraps the corresponding WolfSSL C function to allow
   --  clients to use Ada socket types when implementing a DTLS client.   
   
   subtype chars_ptr is Interfaces.C.Strings.chars_ptr;
   
   type PSK_Client_Callback is access function
     (Ssl            : WolfSSL_Type;
      Hint           : chars_ptr;
      Identity       : chars_ptr;
      Id_Max_Length  : unsigned;
      Key            : chars_ptr;
      Key_Max_Length : unsigned)
      return unsigned with
     Convention => C;
     --  Return value is the key length on success or zero on error.
     --  parameters:
     --  Ssl - Pointer to the wolfSSL structure
     --  Hint - A stored string that could be displayed to provide a
     --         hint to the user.
     --  Identity - The ID will be stored here.
     --  Id_Max_Length - Size of the ID buffer.
     --  Key - The key will be stored here.
     --  Key_Max_Length - The max size of the key.
     --
     --  The implementation of this callback will need `SPARK_Mode => Off`
     --  since it will require the code to use the C memory model.

   procedure Set_PSK_Client_Callback
     (Ssl      : WolfSSL_Type;
      Callback : PSK_Client_Callback) with
     Pre => Is_Valid (Ssl);
     -- Sets the PSK client side callback.
   
   type PSK_Server_Callback is access function
     (Ssl            : WolfSSL_Type;
      Identity       : chars_ptr;
      Key            : chars_ptr;
      Key_Max_Length : unsigned)
      return unsigned with
     Convention => C;
     --  Return value is the key length on success or zero on error.
     --  PSK server callback parameters:
     --  Ssl - Reference to the wolfSSL structure
     --  Identity - The ID will be stored here. 
     --  Key - The key will be stored here.
     --  Key_Max_Length - The max size of the key.
     --
     --  The implementation of this callback will need `SPARK_Mode => Off`
     --  since it will require the code to use the C memory model.

   procedure Set_PSK_Server_Callback
     (Ssl      : WolfSSL_Type;
      Callback : PSK_Server_Callback) with
     Pre => Is_Valid (Ssl);
     -- Sets the PSK Server side callback.
   
   procedure Set_Context_PSK_Server_Callback
     (Context  : Context_Type;
      Callback : PSK_Server_Callback) with
     Pre => Is_Valid (Context);
     --  Sets the PSK callback for the server side in the WolfSSL Context.    

end WolfSSL.Full_Runtime;
