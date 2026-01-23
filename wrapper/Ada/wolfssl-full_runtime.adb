pragma Warnings (Off, "* is an internal GNAT unit");
with GNAT.Sockets.Thin_Common;
pragma Warnings (On, "* is an internal GNAT unit");

package body WolfSSL.Full_Runtime is

   function WolfSSL_DTLS_Set_Peer
     (ssl    : WolfSSL_Type;
      peer   : GNAT.Sockets.Thin_Common.Sockaddr_Access;
      peerSz : Interfaces.C.unsigned)
      return int with
     Convention    => C,
     External_Name => "wolfSSL_dtls_set_peer",
     Import        => True;

   function DTLS_Set_Peer
     (Ssl     : WolfSSL_Type;
      Address : GNAT.Sockets.Sock_Addr_Type)
      return Subprogram_Result is

      Sin    : aliased GNAT.Sockets.Thin_Common.Sockaddr;
      Length : Interfaces.C.int;

   begin

      GNAT.Sockets.Thin_Common.Set_Address
        (Sin     => Sin'Unchecked_Access,
         Address => Address,
         Length  => Length);

      pragma Assert (Length >= 0);

      return
        Subprogram_Result
          (WolfSSL_DTLS_Set_Peer
             (ssl    => Ssl,
              peer   => Sin'Unchecked_Access,
              peerSz => Interfaces.C.unsigned (Length)));
   exception
      when others =>
         return Exception_Error;
   end DTLS_Set_Peer;

   procedure WolfSSL_Set_Psk_Client_Callback
     (Ssl : WolfSSL_Type;
      Cb  : PSK_Client_Callback)
   with
     Convention    => C,
     External_Name => "wolfSSL_set_psk_client_callback",
     Import        => True;

   procedure Set_PSK_Client_Callback
     (Ssl      : WolfSSL_Type;
      Callback : PSK_Client_Callback) is
   begin
      WolfSSL_Set_Psk_Client_Callback (Ssl, Callback);
   end Set_PSK_Client_Callback;

   procedure WolfSSL_Set_Psk_Server_Callback
     (Ssl : WolfSSL_Type;
      Cb  : PSK_Server_Callback)
   with
     Convention    => C,
     External_Name => "wolfSSL_set_psk_server_callback",
     Import        => True;

   procedure Set_PSK_Server_Callback
       (Ssl      : WolfSSL_Type;
        Callback : PSK_Server_Callback) is
   begin
      WolfSSL_Set_Psk_Server_Callback (Ssl, Callback);
   end Set_PSK_Server_Callback;

   procedure WolfSSL_CTX_Set_Psk_Server_Callback
     (Ctx : Context_Type;
      Cb  : PSK_Server_Callback)
   with
     Convention    => C,
     External_Name => "wolfSSL_CTX_set_psk_server_callback",
     Import        => True;

   procedure Set_Context_PSK_Server_Callback
       (Context  : Context_Type;
        Callback : PSK_Server_Callback) is
   begin
      WolfSSL_CTX_Set_Psk_Server_Callback (Context, Callback);
   end Set_Context_PSK_Server_Callback;

end WolfSSL.Full_Runtime;
