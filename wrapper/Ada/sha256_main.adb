with Ada.Text_IO;
with WolfSSL;

procedure SHA256_Main is
   procedure Put (Text : String) renames Ada.Text_IO.Put;
   
   procedure New_Line is
   begin
      Ada.Text_IO.New_Line;
   end New_Line;

   use type WolfSSL.Subprogram_Result;
   
   B : WolfSSL.Byte_Array := (1 => 'a',
                              2 => 's',
                              3 => 'd',
                              4 => 'f');
   SHA256 : WolfSSL.SHA256_Type;
   R : Integer;
   S : WolfSSL.SHA256_As_String;
begin
   WolfSSL.Create_SHA256 (Index => 1, SHA256 => SHA256, Result => R);
   if R /= 0 then
      Put ("SHA256 instance creation failed");
      New_Line;
      return;
   end if;
   WolfSSL.Update_SHA256 (SHA256 => SHA256, Byte => B, Result => R);
   if R /= 0 then
      Put ("Update of SHA256 instance failed");
      New_Line;
      return;
   end if;
   WolfSSL.Finalize_SHA256 (SHA256 => SHA256, Hash => S, Result => R);
   if R = 0 then
      Put (S);
      New_Line;
   else
      Put ("Finalization of SHA256 instance failed");
      New_Line;
      return;
   end if;   
end SHA256_Main;
