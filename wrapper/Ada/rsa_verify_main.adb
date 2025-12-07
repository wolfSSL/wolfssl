with Ada.Integer_Text_IO;
with Ada.Text_IO;
with WolfSSL;

procedure Rsa_Verify_Main is
   
   type Unsigned_8 is mod 2 ** 8;
      
   function To_C (Value : Unsigned_8) return WolfSSL.Byte_Type is
   begin
      return WolfSSL.Byte_Type'Val (Value);
   end To_C;
   
   --  RSA public key to verify with.
   Rsa_Public_key_2048 : constant WolfSSL.Byte_Array :=
     (To_C (16#C3#), To_C (16#03#), To_C (16#D1#), To_C (16#2B#),
      To_C (16#FE#), To_C (16#39#), To_C (16#A4#), To_C (16#32#),
      To_C (16#45#), To_C (16#3B#), To_C (16#53#), To_C (16#C8#),
      To_C (16#84#), To_C (16#2B#), To_C (16#2A#), To_C (16#7C#),
      To_C (16#74#), To_C (16#9A#), To_C (16#BD#), To_C (16#AA#),
      To_C (16#2A#), To_C (16#52#), To_C (16#07#), To_C (16#47#),
      To_C (16#D6#), To_C (16#A6#), To_C (16#36#), To_C (16#B2#),
      To_C (16#07#), To_C (16#32#), To_C (16#8E#), To_C (16#D0#),
      To_C (16#BA#), To_C (16#69#), To_C (16#7B#), To_C (16#C6#),
      To_C (16#C3#), To_C (16#44#), To_C (16#9E#), To_C (16#D4#),
      To_C (16#81#), To_C (16#48#), To_C (16#FD#), To_C (16#2D#),
      To_C (16#68#), To_C (16#A2#), To_C (16#8B#), To_C (16#67#),
      To_C (16#BB#), To_C (16#A1#), To_C (16#75#), To_C (16#C8#),
      To_C (16#36#), To_C (16#2C#), To_C (16#4A#), To_C (16#D2#),
      To_C (16#1B#), To_C (16#F7#), To_C (16#8B#), To_C (16#BA#),
      To_C (16#CF#), To_C (16#0D#), To_C (16#F9#), To_C (16#EF#),
      To_C (16#EC#), To_C (16#F1#), To_C (16#81#), To_C (16#1E#),
      To_C (16#7B#), To_C (16#9B#), To_C (16#03#), To_C (16#47#),
      To_C (16#9A#), To_C (16#BF#), To_C (16#65#), To_C (16#CC#),
      To_C (16#7F#), To_C (16#65#), To_C (16#24#), To_C (16#69#),
      To_C (16#A6#), To_C (16#E8#), To_C (16#14#), To_C (16#89#),
      To_C (16#5B#), To_C (16#E4#), To_C (16#34#), To_C (16#F7#),
      To_C (16#C5#), To_C (16#B0#), To_C (16#14#), To_C (16#93#),
      To_C (16#F5#), To_C (16#67#), To_C (16#7B#), To_C (16#3A#),
      To_C (16#7A#), To_C (16#78#), To_C (16#E1#), To_C (16#01#),
      To_C (16#56#), To_C (16#56#), To_C (16#91#), To_C (16#A6#),
      To_C (16#13#), To_C (16#42#), To_C (16#8D#), To_C (16#D2#),
      To_C (16#3C#), To_C (16#40#), To_C (16#9C#), To_C (16#4C#),
      To_C (16#EF#), To_C (16#D1#), To_C (16#86#), To_C (16#DF#),
      To_C (16#37#), To_C (16#51#), To_C (16#1B#), To_C (16#0C#),
      To_C (16#A1#), To_C (16#3B#), To_C (16#F5#), To_C (16#F1#),
      To_C (16#A3#), To_C (16#4A#), To_C (16#35#), To_C (16#E4#),
      To_C (16#E1#), To_C (16#CE#), To_C (16#96#), To_C (16#DF#),
      To_C (16#1B#), To_C (16#7E#), To_C (16#BF#), To_C (16#4E#),
      To_C (16#97#), To_C (16#D0#), To_C (16#10#), To_C (16#E8#),
      To_C (16#A8#), To_C (16#08#), To_C (16#30#), To_C (16#81#),
      To_C (16#AF#), To_C (16#20#), To_C (16#0B#), To_C (16#43#),
      To_C (16#14#), To_C (16#C5#), To_C (16#74#), To_C (16#67#),
      To_C (16#B4#), To_C (16#32#), To_C (16#82#), To_C (16#6F#),
      To_C (16#8D#), To_C (16#86#), To_C (16#C2#), To_C (16#88#),
      To_C (16#40#), To_C (16#99#), To_C (16#36#), To_C (16#83#),
      To_C (16#BA#), To_C (16#1E#), To_C (16#40#), To_C (16#72#),
      To_C (16#22#), To_C (16#17#), To_C (16#D7#), To_C (16#52#),
      To_C (16#65#), To_C (16#24#), To_C (16#73#), To_C (16#B0#),
      To_C (16#CE#), To_C (16#EF#), To_C (16#19#), To_C (16#CD#),
      To_C (16#AE#), To_C (16#FF#), To_C (16#78#), To_C (16#6C#),
      To_C (16#7B#), To_C (16#C0#), To_C (16#12#), To_C (16#03#),
      To_C (16#D4#), To_C (16#4E#), To_C (16#72#), To_C (16#0D#),
      To_C (16#50#), To_C (16#6D#), To_C (16#3B#), To_C (16#A3#),
      To_C (16#3B#), To_C (16#A3#), To_C (16#99#), To_C (16#5E#),
      To_C (16#9D#), To_C (16#C8#), To_C (16#D9#), To_C (16#0C#),
      To_C (16#85#), To_C (16#B3#), To_C (16#D9#), To_C (16#8A#),
      To_C (16#D9#), To_C (16#54#), To_C (16#26#), To_C (16#DB#),
      To_C (16#6D#), To_C (16#FA#), To_C (16#AC#), To_C (16#BB#),
      To_C (16#FF#), To_C (16#25#), To_C (16#4C#), To_C (16#C4#),
      To_C (16#D1#), To_C (16#79#), To_C (16#F4#), To_C (16#71#),
      To_C (16#D3#), To_C (16#86#), To_C (16#40#), To_C (16#18#),
      To_C (16#13#), To_C (16#B0#), To_C (16#63#), To_C (16#B5#),
      To_C (16#72#), To_C (16#4E#), To_C (16#30#), To_C (16#C4#),
      To_C (16#97#), To_C (16#84#), To_C (16#86#), To_C (16#2D#),
      To_C (16#56#), To_C (16#2F#), To_C (16#D7#), To_C (16#15#),
      To_C (16#F7#), To_C (16#7F#), To_C (16#C0#), To_C (16#AE#),
      To_C (16#F5#), To_C (16#FC#), To_C (16#5B#), To_C (16#E5#),
      To_C (16#FB#), To_C (16#A1#), To_C (16#BA#), To_C (16#D3#));
   
   Message : constant WolfSSL.Byte_Array :=
     (To_C (16#54#), To_C (16#68#), To_C (16#69#), To_C (16#73#),
      To_C (16#20#), To_C (16#69#), To_C (16#73#), To_C (16#20#),
      To_C (16#74#), To_C (16#68#), To_C (16#65#), To_C (16#20#),
      To_C (16#6d#), To_C (16#65#), To_C (16#73#), To_C (16#73#),
      To_C (16#61#), To_C (16#67#), To_C (16#65#));
   

   RSA_Signature : constant WolfSSL.Byte_Array :=
     (To_C (16#41#), To_C (16#eb#), To_C (16#f5#), To_C (16#5e#),
      To_C (16#97#), To_C (16#43#), To_C (16#f4#), To_C (16#d1#),
      To_C (16#da#), To_C (16#b6#), To_C (16#5c#), To_C (16#75#),
      To_C (16#57#), To_C (16#2c#), To_C (16#e1#), To_C (16#01#),
      To_C (16#07#), To_C (16#dc#), To_C (16#42#), To_C (16#c4#),
      To_C (16#2d#), To_C (16#e2#), To_C (16#b5#), To_C (16#c8#),
      To_C (16#63#), To_C (16#e8#), To_C (16#45#), To_C (16#9a#),
      To_C (16#4a#), To_C (16#fa#), To_C (16#df#), To_C (16#5e#),
      To_C (16#a6#), To_C (16#08#), To_C (16#0a#), To_C (16#26#),
      To_C (16#2e#), To_C (16#ca#), To_C (16#2c#), To_C (16#10#),
      To_C (16#7a#), To_C (16#15#), To_C (16#8d#), To_C (16#c1#),
      To_C (16#55#), To_C (16#cc#), To_C (16#33#), To_C (16#db#),
      To_C (16#b2#), To_C (16#ef#), To_C (16#8b#), To_C (16#a6#),
      To_C (16#4b#), To_C (16#ef#), To_C (16#a1#), To_C (16#cf#),
      To_C (16#d3#), To_C (16#e2#), To_C (16#5d#), To_C (16#ac#),
      To_C (16#88#), To_C (16#86#), To_C (16#62#), To_C (16#67#),
      To_C (16#8b#), To_C (16#8c#), To_C (16#45#), To_C (16#7f#),
      To_C (16#10#), To_C (16#ad#), To_C (16#fa#), To_C (16#27#),
      To_C (16#7a#), To_C (16#35#), To_C (16#5a#), To_C (16#f9#),
      To_C (16#09#), To_C (16#78#), To_C (16#83#), To_C (16#ba#),
      To_C (16#18#), To_C (16#cb#), To_C (16#3e#), To_C (16#8e#),
      To_C (16#08#), To_C (16#be#), To_C (16#36#), To_C (16#de#),
      To_C (16#ac#), To_C (16#c1#), To_C (16#77#), To_C (16#44#),
      To_C (16#e8#), To_C (16#43#), To_C (16#db#), To_C (16#52#),
      To_C (16#23#), To_C (16#08#), To_C (16#36#), To_C (16#8f#),
      To_C (16#74#), To_C (16#4a#), To_C (16#bd#), To_C (16#a3#),
      To_C (16#3f#), To_C (16#c1#), To_C (16#fb#), To_C (16#d6#),
      To_C (16#45#), To_C (16#25#), To_C (16#61#), To_C (16#e2#),
      To_C (16#19#), To_C (16#cb#), To_C (16#0b#), To_C (16#28#),
      To_C (16#ef#), To_C (16#ca#), To_C (16#0a#), To_C (16#3b#),
      To_C (16#7b#), To_C (16#3d#), To_C (16#e3#), To_C (16#47#),
      To_C (16#46#), To_C (16#07#), To_C (16#1a#), To_C (16#7f#),
      To_C (16#ff#), To_C (16#38#), To_C (16#fd#), To_C (16#59#),
      To_C (16#94#), To_C (16#0b#), To_C (16#eb#), To_C (16#00#),
      To_C (16#ab#), To_C (16#cc#), To_C (16#8c#), To_C (16#48#),
      To_C (16#7b#), To_C (16#d6#), To_C (16#87#), To_C (16#b8#),
      To_C (16#54#), To_C (16#b0#), To_C (16#2a#), To_C (16#07#),
      To_C (16#cf#), To_C (16#44#), To_C (16#11#), To_C (16#d4#),
      To_C (16#b6#), To_C (16#9a#), To_C (16#4e#), To_C (16#6d#),
      To_C (16#5c#), To_C (16#1a#), To_C (16#e3#), To_C (16#c7#),
      To_C (16#f3#), To_C (16#c7#), To_C (16#cb#), To_C (16#8e#),
      To_C (16#82#), To_C (16#7d#), To_C (16#c8#), To_C (16#77#),
      To_C (16#f0#), To_C (16#b6#), To_C (16#d0#), To_C (16#85#),
      To_C (16#cb#), To_C (16#db#), To_C (16#d0#), To_C (16#b0#),
      To_C (16#e0#), To_C (16#cf#), To_C (16#ca#), To_C (16#3f#),
      To_C (16#17#), To_C (16#46#), To_C (16#84#), To_C (16#cb#),
      To_C (16#5b#), To_C (16#fe#), To_C (16#51#), To_C (16#3a#),
      To_C (16#aa#), To_C (16#71#), To_C (16#ad#), To_C (16#eb#),
      To_C (16#f1#), To_C (16#ed#), To_C (16#3f#), To_C (16#f8#),
      To_C (16#de#), To_C (16#b4#), To_C (16#a1#), To_C (16#26#),
      To_C (16#db#), To_C (16#c6#), To_C (16#8e#), To_C (16#70#),
      To_C (16#d4#), To_C (16#58#), To_C (16#a8#), To_C (16#31#),
      To_C (16#d8#), To_C (16#db#), To_C (16#cf#), To_C (16#64#),
      To_C (16#4a#), To_C (16#5f#), To_C (16#1b#), To_C (16#89#),
      To_C (16#22#), To_C (16#03#), To_C (16#3f#), To_C (16#ab#),
      To_C (16#b5#), To_C (16#6d#), To_C (16#2a#), To_C (16#63#),
      To_C (16#2f#), To_C (16#4e#), To_C (16#7a#), To_C (16#e1#),
      To_C (16#89#), To_C (16#b4#), To_C (16#f0#), To_C (16#9a#),
      To_C (16#b7#), To_C (16#d3#), To_C (16#d6#), To_C (16#0a#),
      To_C (16#10#), To_C (16#67#), To_C (16#28#), To_C (16#25#),
      To_C (16#6d#), To_C (16#da#), To_C (16#92#), To_C (16#99#),
      To_C (16#3f#), To_C (16#64#), To_C (16#a7#), To_C (16#ea#),
      To_C (16#e0#), To_C (16#dc#), To_C (16#7c#), To_C (16#e8#),
      To_C (16#41#), To_C (16#b0#), To_C (16#eb#), To_C (16#45#));   
   
   procedure Put (Text : String) renames Ada.Text_IO.Put;

   procedure Put (Value : Integer) is
   begin
      Ada.Integer_Text_IO.Put (Value);
   end Put;
      
   procedure New_Line is
   begin
      Ada.Text_IO.New_Line;
   end New_Line;

   use type WolfSSL.Subprogram_Result;
   
   Hash : WolfSSL.SHA256_Hash;
   SHA256 : WolfSSL.SHA256_Type;
   R : Integer;
   S : WolfSSL.SHA256_As_String;
   
   Key : WolfSSL.RSA_Key_Type;
   Index : WolfSSL.Byte_Index;
begin
   WolfSSL.Create_SHA256 (Index => 0, SHA256 => SHA256, Result => R);
   if R /= 0 then
      Put ("SHA256 instance creation failed");
      New_Line;
      return;
   end if;
   WolfSSL.Update_SHA256 (SHA256 => SHA256, Byte => Message, Result => R);
   if R /= 0 then
      Put ("Update of SHA256 instance failed");
      New_Line;
      return;
   end if;
   WolfSSL.Finalize_SHA256 (SHA256 => SHA256,
                            Hash   => Hash,
                            Text   => S,
                            Result => R);
   if R = 0 then
      Put (S);
      New_Line;
   else
      Put ("Finalization of SHA256 instance failed");
      New_Line;
      return;
   end if;
   
   WolfSSL.Create_RSA (Index  => 0,
                       Key    => Key,
                       Result => R);
   if R /= 0 then
      Put ("Attaining RSA key instance failed");
      New_Line;
      return;
   end if;
      
   Index := Rsa_Public_key_2048'First;
   Put (WolfSSL.Is_Valid (Key)'Image);

   WolfSSL.Rsa_Public_Key_Decode (Input  => Rsa_Public_key_2048,
                                  Index  => Index,
                                  Key    => Key,
                                  Size   => Rsa_Public_key_2048'Length,
                                  Result => R);
   Put (Integer (Index));
   if R /= 0 then
      Put ("Loading RSA key failed with DER encoded key");
      Put (R);
      New_Line;
      return;
   end if;
end Rsa_Verify_Main;
