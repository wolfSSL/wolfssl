with Tls_Client; pragma Elaborate_All (Tls_Client);

--  Application entry point for the Ada translation of the
--  tls client v1.3 example in C.
procedure Tls_Client_Main is
begin
   Tls_Client.Run;
end Tls_Client_Main;
