with Tls_Server; pragma Elaborate_All (Tls_Server);

--  Application entry point for the Ada translation of the
--  tls server v1.3 example in C.
procedure Tls_Server_Main is
begin
   Tls_Server.Run;
end Tls_Server_Main;
