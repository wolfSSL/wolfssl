with Ada.Text_IO;
with Ada.Integer_Text_IO;
with WolfSSL;
procedure AES_Verify_Main is
   
   use type WolfSSL.Byte_Type;
   
   procedure Put (Text : String) renames Ada.Text_IO.Put;

   procedure Put (Value : Integer) is
   begin
      Ada.Integer_Text_IO.Put (Value);
   end Put;

   procedure New_Line is
   begin
      Ada.Text_IO.New_Line;
   end New_Line;
   
   type Unsigned_8 is mod 2 ** 8;   
   
   function To_C (Value : Unsigned_8) return WolfSSL.Byte_Type is
   begin
      return WolfSSL.Byte_Type'Val (Value);
   end To_C;
   
   RNG : WolfSSL.RNG_Key_Type;
   
   
   Salt_Size : constant := 8;
   
   Salt : WolfSSL.Byte_Array (1 .. 8);
   
   AES : WolfSSL.AES_Type;
   R : Integer;
   Pad : Integer := 3;
begin
   WolfSSL.Create_RNG (Index  => 0,
                       Key    => RNG,
                       Result => R);
   if R /= 0 then
      Put ("Attaining RNG key instance failed");
      New_Line;
      return;
   end if;
   
   WolfSSL.RNG_Generate_Block (RNG    => RNG,
                               Output => Salt,
                               Result => R);
   if R /= 0 then
      Put ("Generating random salt");
      New_Line;
      return;
   end if;
   
   if Pad = 0 then
      Salt (1) := To_C (0);
   elsif Salt (1) = To_C (0) then
      Salt (1) := To_C (1);
   end if;
   
   WolfSSL.Create_AES (Index  => 0,
                       Device => WolfSSL.Invalid_Device,
                       AES    => AES,
                       Result => R);
   if R /= 0 then
      Put ("Attaining AES key instance failed");
      New_Line;
      return;
   end if;

   --  WolfSSL.PBKDF2 (Output     => ,
   --                  Password   => ,
   --                  Salt       => ,
   --                  Iterations => ,
   --                  Key_Length => ,
   --                  HMAC       => ,
   --                  Result     => R);
   --  if R /= 0 then
   --     Put ("Attaining AES key instance failed");
   --     New_Line;
   --     return;
   --  end if;   
end AES_Verify_Main;
