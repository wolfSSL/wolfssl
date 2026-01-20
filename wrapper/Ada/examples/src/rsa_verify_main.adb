with Ada.Integer_Text_IO;
with Ada.Text_IO;
with WolfSSL;

--  If this example executes successfully the output is:
--
--  Successful verification of RSA based digital signature.
--  Successfully encrypted and decrypted using RSA.
procedure Rsa_Verify_Main is

   use type WolfSSL.Byte_Array;

   type Unsigned_8 is mod 2 ** 8;

   function To_C (Value : Unsigned_8) return WolfSSL.Byte_Type is
   begin
      return WolfSSL.Byte_Type'Val (Value);
   end To_C;

   --  RSA public key to verify with.
   Rsa_Public_key_2048 : constant WolfSSL.Byte_Array :=
     (To_C (16#30#), To_C (16#82#), To_C (16#01#), To_C (16#22#), To_C (16#30#),
      To_C (16#0D#), To_C (16#06#), To_C (16#09#), To_C (16#2A#), To_C (16#86#),
      To_C (16#48#), To_C (16#86#), To_C (16#F7#), To_C (16#0D#), To_C (16#01#),
      To_C (16#01#), To_C (16#01#), To_C (16#05#), To_C (16#00#), To_C (16#03#),
      To_C (16#82#), To_C (16#01#), To_C (16#0F#), To_C (16#00#), To_C (16#30#),
      To_C (16#82#), To_C (16#01#), To_C (16#0A#), To_C (16#02#), To_C (16#82#),
      To_C (16#01#), To_C (16#01#), To_C (16#00#), To_C (16#C3#), To_C (16#03#),
      To_C (16#D1#), To_C (16#2B#), To_C (16#FE#), To_C (16#39#), To_C (16#A4#),
      To_C (16#32#), To_C (16#45#), To_C (16#3B#), To_C (16#53#), To_C (16#C8#),
      To_C (16#84#), To_C (16#2B#), To_C (16#2A#), To_C (16#7C#), To_C (16#74#),
      To_C (16#9A#), To_C (16#BD#), To_C (16#AA#), To_C (16#2A#), To_C (16#52#),
      To_C (16#07#), To_C (16#47#), To_C (16#D6#), To_C (16#A6#), To_C (16#36#),
      To_C (16#B2#), To_C (16#07#), To_C (16#32#), To_C (16#8E#), To_C (16#D0#),
      To_C (16#BA#), To_C (16#69#), To_C (16#7B#), To_C (16#C6#), To_C (16#C3#),
      To_C (16#44#), To_C (16#9E#), To_C (16#D4#), To_C (16#81#), To_C (16#48#),
      To_C (16#FD#), To_C (16#2D#), To_C (16#68#), To_C (16#A2#), To_C (16#8B#),
      To_C (16#67#), To_C (16#BB#), To_C (16#A1#), To_C (16#75#), To_C (16#C8#),
      To_C (16#36#), To_C (16#2C#), To_C (16#4A#), To_C (16#D2#), To_C (16#1B#),
      To_C (16#F7#), To_C (16#8B#), To_C (16#BA#), To_C (16#CF#), To_C (16#0D#),
      To_C (16#F9#), To_C (16#EF#), To_C (16#EC#), To_C (16#F1#), To_C (16#81#),
      To_C (16#1E#), To_C (16#7B#), To_C (16#9B#), To_C (16#03#), To_C (16#47#),
      To_C (16#9A#), To_C (16#BF#), To_C (16#65#), To_C (16#CC#), To_C (16#7F#),
      To_C (16#65#), To_C (16#24#), To_C (16#69#), To_C (16#A6#), To_C (16#E8#),
      To_C (16#14#), To_C (16#89#), To_C (16#5B#), To_C (16#E4#), To_C (16#34#),
      To_C (16#F7#), To_C (16#C5#), To_C (16#B0#), To_C (16#14#), To_C (16#93#),
      To_C (16#F5#), To_C (16#67#), To_C (16#7B#), To_C (16#3A#), To_C (16#7A#),
      To_C (16#78#), To_C (16#E1#), To_C (16#01#), To_C (16#56#), To_C (16#56#),
      To_C (16#91#), To_C (16#A6#), To_C (16#13#), To_C (16#42#), To_C (16#8D#),
      To_C (16#D2#), To_C (16#3C#), To_C (16#40#), To_C (16#9C#), To_C (16#4C#),
      To_C (16#EF#), To_C (16#D1#), To_C (16#86#), To_C (16#DF#), To_C (16#37#),
      To_C (16#51#), To_C (16#1B#), To_C (16#0C#), To_C (16#A1#), To_C (16#3B#),
      To_C (16#F5#), To_C (16#F1#), To_C (16#A3#), To_C (16#4A#), To_C (16#35#),
      To_C (16#E4#), To_C (16#E1#), To_C (16#CE#), To_C (16#96#), To_C (16#DF#),
      To_C (16#1B#), To_C (16#7E#), To_C (16#BF#), To_C (16#4E#), To_C (16#97#),
      To_C (16#D0#), To_C (16#10#), To_C (16#E8#), To_C (16#A8#), To_C (16#08#),
      To_C (16#30#), To_C (16#81#), To_C (16#AF#), To_C (16#20#), To_C (16#0B#),
      To_C (16#43#), To_C (16#14#), To_C (16#C5#), To_C (16#74#), To_C (16#67#),
      To_C (16#B4#), To_C (16#32#), To_C (16#82#), To_C (16#6F#), To_C (16#8D#),
      To_C (16#86#), To_C (16#C2#), To_C (16#88#), To_C (16#40#), To_C (16#99#),
      To_C (16#36#), To_C (16#83#), To_C (16#BA#), To_C (16#1E#), To_C (16#40#),
      To_C (16#72#), To_C (16#22#), To_C (16#17#), To_C (16#D7#), To_C (16#52#),
      To_C (16#65#), To_C (16#24#), To_C (16#73#), To_C (16#B0#), To_C (16#CE#),
      To_C (16#EF#), To_C (16#19#), To_C (16#CD#), To_C (16#AE#), To_C (16#FF#),
      To_C (16#78#), To_C (16#6C#), To_C (16#7B#), To_C (16#C0#), To_C (16#12#),
      To_C (16#03#), To_C (16#D4#), To_C (16#4E#), To_C (16#72#), To_C (16#0D#),
      To_C (16#50#), To_C (16#6D#), To_C (16#3B#), To_C (16#A3#), To_C (16#3B#),
      To_C (16#A3#), To_C (16#99#), To_C (16#5E#), To_C (16#9D#), To_C (16#C8#),
      To_C (16#D9#), To_C (16#0C#), To_C (16#85#), To_C (16#B3#), To_C (16#D9#),
      To_C (16#8A#), To_C (16#D9#), To_C (16#54#), To_C (16#26#), To_C (16#DB#),
      To_C (16#6D#), To_C (16#FA#), To_C (16#AC#), To_C (16#BB#), To_C (16#FF#),
      To_C (16#25#), To_C (16#4C#), To_C (16#C4#), To_C (16#D1#), To_C (16#79#),
      To_C (16#F4#), To_C (16#71#), To_C (16#D3#), To_C (16#86#), To_C (16#40#),
      To_C (16#18#), To_C (16#13#), To_C (16#B0#), To_C (16#63#), To_C (16#B5#),
      To_C (16#72#), To_C (16#4E#), To_C (16#30#), To_C (16#C4#), To_C (16#97#),
      To_C (16#84#), To_C (16#86#), To_C (16#2D#), To_C (16#56#), To_C (16#2F#),
      To_C (16#D7#), To_C (16#15#), To_C (16#F7#), To_C (16#7F#), To_C (16#C0#),
      To_C (16#AE#), To_C (16#F5#), To_C (16#FC#), To_C (16#5B#), To_C (16#E5#),
      To_C (16#FB#), To_C (16#A1#), To_C (16#BA#), To_C (16#D3#), To_C (16#02#),
      To_C (16#03#), To_C (16#01#), To_C (16#00#), To_C (16#01#));

   --  DER-formatted key.
   Client_Private_Key_2048 : constant WolfSSL.Byte_Array :=
     (To_C (16#30#), To_C (16#82#), To_C (16#04#), To_C (16#A4#), To_C (16#02#),
     To_C (16#01#), To_C (16#00#), To_C (16#02#), To_C (16#82#), To_C (16#01#),
     To_C (16#01#), To_C (16#00#), To_C (16#C3#), To_C (16#03#), To_C (16#D1#),
     To_C (16#2B#), To_C (16#FE#), To_C (16#39#), To_C (16#A4#), To_C (16#32#),
     To_C (16#45#), To_C (16#3B#), To_C (16#53#), To_C (16#C8#), To_C (16#84#),
     To_C (16#2B#), To_C (16#2A#), To_C (16#7C#), To_C (16#74#), To_C (16#9A#),
     To_C (16#BD#), To_C (16#AA#), To_C (16#2A#), To_C (16#52#), To_C (16#07#),
     To_C (16#47#), To_C (16#D6#), To_C (16#A6#), To_C (16#36#), To_C (16#B2#),
     To_C (16#07#), To_C (16#32#), To_C (16#8E#), To_C (16#D0#), To_C (16#BA#),
     To_C (16#69#), To_C (16#7B#), To_C (16#C6#), To_C (16#C3#), To_C (16#44#),
     To_C (16#9E#), To_C (16#D4#), To_C (16#81#), To_C (16#48#), To_C (16#FD#),
     To_C (16#2D#), To_C (16#68#), To_C (16#A2#), To_C (16#8B#), To_C (16#67#),
     To_C (16#BB#), To_C (16#A1#), To_C (16#75#), To_C (16#C8#), To_C (16#36#),
     To_C (16#2C#), To_C (16#4A#), To_C (16#D2#), To_C (16#1B#), To_C (16#F7#),
     To_C (16#8B#), To_C (16#BA#), To_C (16#CF#), To_C (16#0D#), To_C (16#F9#),
     To_C (16#EF#), To_C (16#EC#), To_C (16#F1#), To_C (16#81#), To_C (16#1E#),
     To_C (16#7B#), To_C (16#9B#), To_C (16#03#), To_C (16#47#), To_C (16#9A#),
     To_C (16#BF#), To_C (16#65#), To_C (16#CC#), To_C (16#7F#), To_C (16#65#),
     To_C (16#24#), To_C (16#69#), To_C (16#A6#), To_C (16#E8#), To_C (16#14#),
     To_C (16#89#), To_C (16#5B#), To_C (16#E4#), To_C (16#34#), To_C (16#F7#),
     To_C (16#C5#), To_C (16#B0#), To_C (16#14#), To_C (16#93#), To_C (16#F5#),
     To_C (16#67#), To_C (16#7B#), To_C (16#3A#), To_C (16#7A#), To_C (16#78#),
     To_C (16#E1#), To_C (16#01#), To_C (16#56#), To_C (16#56#), To_C (16#91#),
     To_C (16#A6#), To_C (16#13#), To_C (16#42#), To_C (16#8D#), To_C (16#D2#),
     To_C (16#3C#), To_C (16#40#), To_C (16#9C#), To_C (16#4C#), To_C (16#EF#),
     To_C (16#D1#), To_C (16#86#), To_C (16#DF#), To_C (16#37#), To_C (16#51#),
     To_C (16#1B#), To_C (16#0C#), To_C (16#A1#), To_C (16#3B#), To_C (16#F5#),
     To_C (16#F1#), To_C (16#A3#), To_C (16#4A#), To_C (16#35#), To_C (16#E4#),
     To_C (16#E1#), To_C (16#CE#), To_C (16#96#), To_C (16#DF#), To_C (16#1B#),
     To_C (16#7E#), To_C (16#BF#), To_C (16#4E#), To_C (16#97#), To_C (16#D0#),
     To_C (16#10#), To_C (16#E8#), To_C (16#A8#), To_C (16#08#), To_C (16#30#),
     To_C (16#81#), To_C (16#AF#), To_C (16#20#), To_C (16#0B#), To_C (16#43#),
     To_C (16#14#), To_C (16#C5#), To_C (16#74#), To_C (16#67#), To_C (16#B4#),
     To_C (16#32#), To_C (16#82#), To_C (16#6F#), To_C (16#8D#), To_C (16#86#),
     To_C (16#C2#), To_C (16#88#), To_C (16#40#), To_C (16#99#), To_C (16#36#),
     To_C (16#83#), To_C (16#BA#), To_C (16#1E#), To_C (16#40#), To_C (16#72#),
     To_C (16#22#), To_C (16#17#), To_C (16#D7#), To_C (16#52#), To_C (16#65#),
     To_C (16#24#), To_C (16#73#), To_C (16#B0#), To_C (16#CE#), To_C (16#EF#),
     To_C (16#19#), To_C (16#CD#), To_C (16#AE#), To_C (16#FF#), To_C (16#78#),
     To_C (16#6C#), To_C (16#7B#), To_C (16#C0#), To_C (16#12#), To_C (16#03#),
     To_C (16#D4#), To_C (16#4E#), To_C (16#72#), To_C (16#0D#), To_C (16#50#),
     To_C (16#6D#), To_C (16#3B#), To_C (16#A3#), To_C (16#3B#), To_C (16#A3#),
     To_C (16#99#), To_C (16#5E#), To_C (16#9D#), To_C (16#C8#), To_C (16#D9#),
     To_C (16#0C#), To_C (16#85#), To_C (16#B3#), To_C (16#D9#), To_C (16#8A#),
     To_C (16#D9#), To_C (16#54#), To_C (16#26#), To_C (16#DB#), To_C (16#6D#),
     To_C (16#FA#), To_C (16#AC#), To_C (16#BB#), To_C (16#FF#), To_C (16#25#),
     To_C (16#4C#), To_C (16#C4#), To_C (16#D1#), To_C (16#79#), To_C (16#F4#),
     To_C (16#71#), To_C (16#D3#), To_C (16#86#), To_C (16#40#), To_C (16#18#),
     To_C (16#13#), To_C (16#B0#), To_C (16#63#), To_C (16#B5#), To_C (16#72#),
     To_C (16#4E#), To_C (16#30#), To_C (16#C4#), To_C (16#97#), To_C (16#84#),
     To_C (16#86#), To_C (16#2D#), To_C (16#56#), To_C (16#2F#), To_C (16#D7#),
     To_C (16#15#), To_C (16#F7#), To_C (16#7F#), To_C (16#C0#), To_C (16#AE#),
     To_C (16#F5#), To_C (16#FC#), To_C (16#5B#), To_C (16#E5#), To_C (16#FB#),
     To_C (16#A1#), To_C (16#BA#), To_C (16#D3#), To_C (16#02#), To_C (16#03#),
     To_C (16#01#), To_C (16#00#), To_C (16#01#), To_C (16#02#), To_C (16#82#),
     To_C (16#01#), To_C (16#01#), To_C (16#00#), To_C (16#A2#), To_C (16#E6#),
     To_C (16#D8#), To_C (16#5F#), To_C (16#10#), To_C (16#71#), To_C (16#64#),
     To_C (16#08#), To_C (16#9E#), To_C (16#2E#), To_C (16#6D#), To_C (16#D1#),
     To_C (16#6D#), To_C (16#1E#), To_C (16#85#), To_C (16#D2#), To_C (16#0A#),
     To_C (16#B1#), To_C (16#8C#), To_C (16#47#), To_C (16#CE#), To_C (16#2C#),
     To_C (16#51#), To_C (16#6A#), To_C (16#A0#), To_C (16#12#), To_C (16#9E#),
     To_C (16#53#), To_C (16#DE#), To_C (16#91#), To_C (16#4C#), To_C (16#1D#),
     To_C (16#6D#), To_C (16#EA#), To_C (16#59#), To_C (16#7B#), To_C (16#F2#),
     To_C (16#77#), To_C (16#AA#), To_C (16#D9#), To_C (16#C6#), To_C (16#D9#),
     To_C (16#8A#), To_C (16#AB#), To_C (16#D8#), To_C (16#E1#), To_C (16#16#),
     To_C (16#E4#), To_C (16#63#), To_C (16#26#), To_C (16#FF#), To_C (16#B5#),
     To_C (16#6C#), To_C (16#13#), To_C (16#59#), To_C (16#B8#), To_C (16#E3#),
     To_C (16#A5#), To_C (16#C8#), To_C (16#72#), To_C (16#17#), To_C (16#2E#),
     To_C (16#0C#), To_C (16#9F#), To_C (16#6F#), To_C (16#E5#), To_C (16#59#),
     To_C (16#3F#), To_C (16#76#), To_C (16#6F#), To_C (16#49#), To_C (16#B1#),
     To_C (16#11#), To_C (16#C2#), To_C (16#5A#), To_C (16#2E#), To_C (16#16#),
     To_C (16#29#), To_C (16#0D#), To_C (16#DE#), To_C (16#B7#), To_C (16#8E#),
     To_C (16#DC#), To_C (16#40#), To_C (16#D5#), To_C (16#A2#), To_C (16#EE#),
     To_C (16#E0#), To_C (16#1E#), To_C (16#A1#), To_C (16#F4#), To_C (16#BE#),
     To_C (16#97#), To_C (16#DB#), To_C (16#86#), To_C (16#63#), To_C (16#96#),
     To_C (16#14#), To_C (16#CD#), To_C (16#98#), To_C (16#09#), To_C (16#60#),
     To_C (16#2D#), To_C (16#30#), To_C (16#76#), To_C (16#9C#), To_C (16#3C#),
     To_C (16#CD#), To_C (16#E6#), To_C (16#88#), To_C (16#EE#), To_C (16#47#),
     To_C (16#92#), To_C (16#79#), To_C (16#0B#), To_C (16#5A#), To_C (16#00#),
     To_C (16#E2#), To_C (16#5E#), To_C (16#5F#), To_C (16#11#), To_C (16#7C#),
     To_C (16#7D#), To_C (16#F9#), To_C (16#08#), To_C (16#B7#), To_C (16#20#),
     To_C (16#06#), To_C (16#89#), To_C (16#2A#), To_C (16#5D#), To_C (16#FD#),
     To_C (16#00#), To_C (16#AB#), To_C (16#22#), To_C (16#E1#), To_C (16#F0#),
     To_C (16#B3#), To_C (16#BC#), To_C (16#24#), To_C (16#A9#), To_C (16#5E#),
     To_C (16#26#), To_C (16#0E#), To_C (16#1F#), To_C (16#00#), To_C (16#2D#),
     To_C (16#FE#), To_C (16#21#), To_C (16#9A#), To_C (16#53#), To_C (16#5B#),
     To_C (16#6D#), To_C (16#D3#), To_C (16#2B#), To_C (16#AB#), To_C (16#94#),
     To_C (16#82#), To_C (16#68#), To_C (16#43#), To_C (16#36#), To_C (16#D8#),
     To_C (16#F6#), To_C (16#2F#), To_C (16#C6#), To_C (16#22#), To_C (16#FC#),
     To_C (16#B5#), To_C (16#41#), To_C (16#5D#), To_C (16#0D#), To_C (16#33#),
     To_C (16#60#), To_C (16#EA#), To_C (16#A4#), To_C (16#7D#), To_C (16#7E#),
     To_C (16#E8#), To_C (16#4B#), To_C (16#55#), To_C (16#91#), To_C (16#56#),
     To_C (16#D3#), To_C (16#5C#), To_C (16#57#), To_C (16#8F#), To_C (16#1F#),
     To_C (16#94#), To_C (16#17#), To_C (16#2F#), To_C (16#AA#), To_C (16#DE#),
     To_C (16#E9#), To_C (16#9E#), To_C (16#A8#), To_C (16#F4#), To_C (16#CF#),
     To_C (16#8A#), To_C (16#4C#), To_C (16#8E#), To_C (16#A0#), To_C (16#E4#),
     To_C (16#56#), To_C (16#73#), To_C (16#B2#), To_C (16#CF#), To_C (16#4F#),
     To_C (16#86#), To_C (16#C5#), To_C (16#69#), To_C (16#3C#), To_C (16#F3#),
     To_C (16#24#), To_C (16#20#), To_C (16#8B#), To_C (16#5C#), To_C (16#96#),
     To_C (16#0C#), To_C (16#FA#), To_C (16#6B#), To_C (16#12#), To_C (16#3B#),
     To_C (16#9A#), To_C (16#67#), To_C (16#C1#), To_C (16#DF#), To_C (16#C6#),
     To_C (16#96#), To_C (16#B2#), To_C (16#A5#), To_C (16#D5#), To_C (16#92#),
     To_C (16#0D#), To_C (16#9B#), To_C (16#09#), To_C (16#42#), To_C (16#68#),
     To_C (16#24#), To_C (16#10#), To_C (16#45#), To_C (16#D4#), To_C (16#50#),
     To_C (16#E4#), To_C (16#17#), To_C (16#39#), To_C (16#48#), To_C (16#D0#),
     To_C (16#35#), To_C (16#8B#), To_C (16#94#), To_C (16#6D#), To_C (16#11#),
     To_C (16#DE#), To_C (16#8F#), To_C (16#CA#), To_C (16#59#), To_C (16#02#),
     To_C (16#81#), To_C (16#81#), To_C (16#00#), To_C (16#EA#), To_C (16#24#),
     To_C (16#A7#), To_C (16#F9#), To_C (16#69#), To_C (16#33#), To_C (16#E9#),
     To_C (16#71#), To_C (16#DC#), To_C (16#52#), To_C (16#7D#), To_C (16#88#),
     To_C (16#21#), To_C (16#28#), To_C (16#2F#), To_C (16#49#), To_C (16#DE#),
     To_C (16#BA#), To_C (16#72#), To_C (16#16#), To_C (16#E9#), To_C (16#CC#),
     To_C (16#47#), To_C (16#7A#), To_C (16#88#), To_C (16#0D#), To_C (16#94#),
     To_C (16#57#), To_C (16#84#), To_C (16#58#), To_C (16#16#), To_C (16#3A#),
     To_C (16#81#), To_C (16#B0#), To_C (16#3F#), To_C (16#A2#), To_C (16#CF#),
     To_C (16#A6#), To_C (16#6C#), To_C (16#1E#), To_C (16#B0#), To_C (16#06#),
     To_C (16#29#), To_C (16#00#), To_C (16#8F#), To_C (16#E7#), To_C (16#77#),
     To_C (16#76#), To_C (16#AC#), To_C (16#DB#), To_C (16#CA#), To_C (16#C7#),
     To_C (16#D9#), To_C (16#5E#), To_C (16#9B#), To_C (16#3F#), To_C (16#26#),
     To_C (16#90#), To_C (16#52#), To_C (16#AE#), To_C (16#FC#), To_C (16#38#),
     To_C (16#90#), To_C (16#00#), To_C (16#14#), To_C (16#BB#), To_C (16#B4#),
     To_C (16#0F#), To_C (16#58#), To_C (16#94#), To_C (16#E7#), To_C (16#2F#),
     To_C (16#6A#), To_C (16#7E#), To_C (16#1C#), To_C (16#4F#), To_C (16#41#),
     To_C (16#21#), To_C (16#D4#), To_C (16#31#), To_C (16#59#), To_C (16#1F#),
     To_C (16#4E#), To_C (16#8A#), To_C (16#1A#), To_C (16#8D#), To_C (16#A7#),
     To_C (16#57#), To_C (16#6C#), To_C (16#22#), To_C (16#D8#), To_C (16#E5#),
     To_C (16#F4#), To_C (16#7E#), To_C (16#32#), To_C (16#A6#), To_C (16#10#),
     To_C (16#CB#), To_C (16#64#), To_C (16#A5#), To_C (16#55#), To_C (16#03#),
     To_C (16#87#), To_C (16#A6#), To_C (16#27#), To_C (16#05#), To_C (16#8C#),
     To_C (16#C3#), To_C (16#D7#), To_C (16#B6#), To_C (16#27#), To_C (16#B2#),
     To_C (16#4D#), To_C (16#BA#), To_C (16#30#), To_C (16#DA#), To_C (16#47#),
     To_C (16#8F#), To_C (16#54#), To_C (16#D3#), To_C (16#3D#), To_C (16#8B#),
     To_C (16#84#), To_C (16#8D#), To_C (16#94#), To_C (16#98#), To_C (16#58#),
     To_C (16#A5#), To_C (16#02#), To_C (16#81#), To_C (16#81#), To_C (16#00#),
     To_C (16#D5#), To_C (16#38#), To_C (16#1B#), To_C (16#C3#), To_C (16#8F#),
     To_C (16#C5#), To_C (16#93#), To_C (16#0C#), To_C (16#47#), To_C (16#0B#),
     To_C (16#6F#), To_C (16#35#), To_C (16#92#), To_C (16#C5#), To_C (16#B0#),
     To_C (16#8D#), To_C (16#46#), To_C (16#C8#), To_C (16#92#), To_C (16#18#),
     To_C (16#8F#), To_C (16#F5#), To_C (16#80#), To_C (16#0A#), To_C (16#F7#),
     To_C (16#EF#), To_C (16#A1#), To_C (16#FE#), To_C (16#80#), To_C (16#B9#),
     To_C (16#B5#), To_C (16#2A#), To_C (16#BA#), To_C (16#CA#), To_C (16#18#),
     To_C (16#B0#), To_C (16#5D#), To_C (16#A5#), To_C (16#07#), To_C (16#D0#),
     To_C (16#93#), To_C (16#8D#), To_C (16#D8#), To_C (16#9C#), To_C (16#04#),
     To_C (16#1C#), To_C (16#D4#), To_C (16#62#), To_C (16#8E#), To_C (16#A6#),
     To_C (16#26#), To_C (16#81#), To_C (16#01#), To_C (16#FF#), To_C (16#CE#),
     To_C (16#8A#), To_C (16#2A#), To_C (16#63#), To_C (16#34#), To_C (16#35#),
     To_C (16#40#), To_C (16#AA#), To_C (16#6D#), To_C (16#80#), To_C (16#DE#),
     To_C (16#89#), To_C (16#23#), To_C (16#6A#), To_C (16#57#), To_C (16#4D#),
     To_C (16#9E#), To_C (16#6E#), To_C (16#AD#), To_C (16#93#), To_C (16#4E#),
     To_C (16#56#), To_C (16#90#), To_C (16#0B#), To_C (16#6D#), To_C (16#9D#),
     To_C (16#73#), To_C (16#8B#), To_C (16#0C#), To_C (16#AE#), To_C (16#27#),
     To_C (16#3D#), To_C (16#DE#), To_C (16#4E#), To_C (16#F0#), To_C (16#AA#),
     To_C (16#C5#), To_C (16#6C#), To_C (16#78#), To_C (16#67#), To_C (16#6C#),
     To_C (16#94#), To_C (16#52#), To_C (16#9C#), To_C (16#37#), To_C (16#67#),
     To_C (16#6C#), To_C (16#2D#), To_C (16#EF#), To_C (16#BB#), To_C (16#AF#),
     To_C (16#DF#), To_C (16#A6#), To_C (16#90#), To_C (16#3C#), To_C (16#C4#),
     To_C (16#47#), To_C (16#CF#), To_C (16#8D#), To_C (16#96#), To_C (16#9E#),
     To_C (16#98#), To_C (16#A9#), To_C (16#B4#), To_C (16#9F#), To_C (16#C5#),
     To_C (16#A6#), To_C (16#50#), To_C (16#DC#), To_C (16#B3#), To_C (16#F0#),
     To_C (16#FB#), To_C (16#74#), To_C (16#17#), To_C (16#02#), To_C (16#81#),
     To_C (16#80#), To_C (16#5E#), To_C (16#83#), To_C (16#09#), To_C (16#62#),
     To_C (16#BD#), To_C (16#BA#), To_C (16#7C#), To_C (16#A2#), To_C (16#BF#),
     To_C (16#42#), To_C (16#74#), To_C (16#F5#), To_C (16#7C#), To_C (16#1C#),
     To_C (16#D2#), To_C (16#69#), To_C (16#C9#), To_C (16#04#), To_C (16#0D#),
     To_C (16#85#), To_C (16#7E#), To_C (16#3E#), To_C (16#3D#), To_C (16#24#),
     To_C (16#12#), To_C (16#C3#), To_C (16#18#), To_C (16#7B#), To_C (16#F3#),
     To_C (16#29#), To_C (16#F3#), To_C (16#5F#), To_C (16#0E#), To_C (16#76#),
     To_C (16#6C#), To_C (16#59#), To_C (16#75#), To_C (16#E4#), To_C (16#41#),
     To_C (16#84#), To_C (16#69#), To_C (16#9D#), To_C (16#32#), To_C (16#F3#),
     To_C (16#CD#), To_C (16#22#), To_C (16#AB#), To_C (16#B0#), To_C (16#35#),
     To_C (16#BA#), To_C (16#4A#), To_C (16#B2#), To_C (16#3C#), To_C (16#E5#),
     To_C (16#D9#), To_C (16#58#), To_C (16#B6#), To_C (16#62#), To_C (16#4F#),
     To_C (16#5D#), To_C (16#DE#), To_C (16#E5#), To_C (16#9E#), To_C (16#0A#),
     To_C (16#CA#), To_C (16#53#), To_C (16#B2#), To_C (16#2C#), To_C (16#F7#),
     To_C (16#9E#), To_C (16#B3#), To_C (16#6B#), To_C (16#0A#), To_C (16#5B#),
     To_C (16#79#), To_C (16#65#), To_C (16#EC#), To_C (16#6E#), To_C (16#91#),
     To_C (16#4E#), To_C (16#92#), To_C (16#20#), To_C (16#F6#), To_C (16#FC#),
     To_C (16#FC#), To_C (16#16#), To_C (16#ED#), To_C (16#D3#), To_C (16#76#),
     To_C (16#0C#), To_C (16#E2#), To_C (16#EC#), To_C (16#7F#), To_C (16#B2#),
     To_C (16#69#), To_C (16#13#), To_C (16#6B#), To_C (16#78#), To_C (16#0E#),
     To_C (16#5A#), To_C (16#46#), To_C (16#64#), To_C (16#B4#), To_C (16#5E#),
     To_C (16#B7#), To_C (16#25#), To_C (16#A0#), To_C (16#5A#), To_C (16#75#),
     To_C (16#3A#), To_C (16#4B#), To_C (16#EF#), To_C (16#C7#), To_C (16#3C#),
     To_C (16#3E#), To_C (16#F7#), To_C (16#FD#), To_C (16#26#), To_C (16#B8#),
     To_C (16#20#), To_C (16#C4#), To_C (16#99#), To_C (16#0A#), To_C (16#9A#),
     To_C (16#73#), To_C (16#BE#), To_C (16#C3#), To_C (16#19#), To_C (16#02#),
     To_C (16#81#), To_C (16#81#), To_C (16#00#), To_C (16#BA#), To_C (16#44#),
     To_C (16#93#), To_C (16#14#), To_C (16#AC#), To_C (16#34#), To_C (16#19#),
     To_C (16#3B#), To_C (16#5F#), To_C (16#91#), To_C (16#60#), To_C (16#AC#),
     To_C (16#F7#), To_C (16#B4#), To_C (16#D6#), To_C (16#81#), To_C (16#05#),
     To_C (16#36#), To_C (16#51#), To_C (16#53#), To_C (16#3D#), To_C (16#E8#),
     To_C (16#65#), To_C (16#DC#), To_C (16#AF#), To_C (16#2E#), To_C (16#DC#),
     To_C (16#61#), To_C (16#3E#), To_C (16#C9#), To_C (16#7D#), To_C (16#B8#),
     To_C (16#7F#), To_C (16#87#), To_C (16#F0#), To_C (16#3B#), To_C (16#9B#),
     To_C (16#03#), To_C (16#82#), To_C (16#29#), To_C (16#37#), To_C (16#CE#),
     To_C (16#72#), To_C (16#4E#), To_C (16#11#), To_C (16#D5#), To_C (16#B1#),
     To_C (16#C1#), To_C (16#0C#), To_C (16#07#), To_C (16#A0#), To_C (16#99#),
     To_C (16#91#), To_C (16#4A#), To_C (16#8D#), To_C (16#7F#), To_C (16#EC#),
     To_C (16#79#), To_C (16#CF#), To_C (16#F1#), To_C (16#39#), To_C (16#B5#),
     To_C (16#E9#), To_C (16#85#), To_C (16#EC#), To_C (16#62#), To_C (16#F7#),
     To_C (16#DA#), To_C (16#7D#), To_C (16#BC#), To_C (16#64#), To_C (16#4D#),
     To_C (16#22#), To_C (16#3C#), To_C (16#0E#), To_C (16#F2#), To_C (16#D6#),
     To_C (16#51#), To_C (16#F5#), To_C (16#87#), To_C (16#D8#), To_C (16#99#),
     To_C (16#C0#), To_C (16#11#), To_C (16#20#), To_C (16#5D#), To_C (16#0F#),
     To_C (16#29#), To_C (16#FD#), To_C (16#5B#), To_C (16#E2#), To_C (16#AE#),
     To_C (16#D9#), To_C (16#1C#), To_C (16#D9#), To_C (16#21#), To_C (16#56#),
     To_C (16#6D#), To_C (16#FC#), To_C (16#84#), To_C (16#D0#), To_C (16#5F#),
     To_C (16#ED#), To_C (16#10#), To_C (16#15#), To_C (16#1C#), To_C (16#18#),
     To_C (16#21#), To_C (16#E7#), To_C (16#C4#), To_C (16#3D#), To_C (16#4B#),
     To_C (16#D7#), To_C (16#D0#), To_C (16#9E#), To_C (16#6A#), To_C (16#95#),
     To_C (16#CF#), To_C (16#22#), To_C (16#C9#), To_C (16#03#), To_C (16#7B#),
     To_C (16#9E#), To_C (16#E3#), To_C (16#60#), To_C (16#01#), To_C (16#FC#),
     To_C (16#2F#), To_C (16#02#), To_C (16#81#), To_C (16#80#), To_C (16#11#),
     To_C (16#D0#), To_C (16#4B#), To_C (16#CF#), To_C (16#1B#), To_C (16#67#),
     To_C (16#B9#), To_C (16#9F#), To_C (16#10#), To_C (16#75#), To_C (16#47#),
     To_C (16#86#), To_C (16#65#), To_C (16#AE#), To_C (16#31#), To_C (16#C2#),
     To_C (16#C6#), To_C (16#30#), To_C (16#AC#), To_C (16#59#), To_C (16#06#),
     To_C (16#50#), To_C (16#D9#), To_C (16#0F#), To_C (16#B5#), To_C (16#70#),
     To_C (16#06#), To_C (16#F7#), To_C (16#F0#), To_C (16#D3#), To_C (16#C8#),
     To_C (16#62#), To_C (16#7C#), To_C (16#A8#), To_C (16#DA#), To_C (16#6E#),
     To_C (16#F6#), To_C (16#21#), To_C (16#3F#), To_C (16#D3#), To_C (16#7F#),
     To_C (16#5F#), To_C (16#EA#), To_C (16#8A#), To_C (16#AB#), To_C (16#3F#),
     To_C (16#D9#), To_C (16#2A#), To_C (16#5E#), To_C (16#F3#), To_C (16#51#),
     To_C (16#D2#), To_C (16#C2#), To_C (16#30#), To_C (16#37#), To_C (16#E3#),
     To_C (16#2D#), To_C (16#A3#), To_C (16#75#), To_C (16#0D#), To_C (16#1E#),
     To_C (16#4D#), To_C (16#21#), To_C (16#34#), To_C (16#D5#), To_C (16#57#),
     To_C (16#70#), To_C (16#5C#), To_C (16#89#), To_C (16#BF#), To_C (16#72#),
     To_C (16#EC#), To_C (16#4A#), To_C (16#6E#), To_C (16#68#), To_C (16#D5#),
     To_C (16#CD#), To_C (16#18#), To_C (16#74#), To_C (16#33#), To_C (16#4E#),
     To_C (16#8C#), To_C (16#3A#), To_C (16#45#), To_C (16#8F#), To_C (16#E6#),
     To_C (16#96#), To_C (16#40#), To_C (16#EB#), To_C (16#63#), To_C (16#F9#),
     To_C (16#19#), To_C (16#86#), To_C (16#3A#), To_C (16#51#), To_C (16#DD#),
     To_C (16#89#), To_C (16#4B#), To_C (16#B0#), To_C (16#F3#), To_C (16#F9#),
     To_C (16#9F#), To_C (16#5D#), To_C (16#28#), To_C (16#95#), To_C (16#38#),
     To_C (16#BE#), To_C (16#35#), To_C (16#AB#), To_C (16#CA#), To_C (16#5C#),
     To_C (16#E7#), To_C (16#93#), To_C (16#53#), To_C (16#34#), To_C (16#A1#),
     To_C (16#45#), To_C (16#5D#), To_C (16#13#), To_C (16#39#), To_C (16#65#),
     To_C (16#42#), To_C (16#46#), To_C (16#A1#), To_C (16#9F#), To_C (16#CD#),
     To_C (16#F5#), To_C (16#BF#));

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

   Original_AES_Key : constant WolfSSL.Byte_Array (1 .. 32) :=
     "Thisismyfakeaeskeythatis32bytes!";

   Digital_Signature_Of_AES_Key : WolfSSL.Byte_Array (1 .. 256);

   Decrypted_Digital_Signature : WolfSSL.Byte_Array (1 .. 256);

   Encrypted : WolfSSL.Byte_Array (1 .. 1_024);
   --  Actually only needs to be at least 256 bytes.
   --  The purpose is to store the Original_AES_Key encrypted.

   Decrypted : WolfSSL.Byte_Array (1 .. 1_024);
   --  Actually only needs to be at least 32 bytes.
   --  The purpose is to store the Original_AES_Key after
   --  first being encrypted and then decrypted.
   --  After the process, this byte array should contain the same
   --  contents as Original_AES_KEY.

   Hash : WolfSSL.SHA256_Hash;
   SHA256 : WolfSSL.SHA256_Type;
   R : Integer;

   RNG : WolfSSL.RNG_Type;

   RSA_Encrypt_Key : WolfSSL.RSA_Key_Type;
   RSA_Decrypt_Key : WolfSSL.RSA_Key_Type;
   Index : WolfSSL.Byte_Index;

   --  Release any resources that may have been acquired so far.
   --  Safe to call multiple times and safe when handles are null.
   procedure Cleanup is
   begin
      if WolfSSL.Is_Valid (RSA_Encrypt_Key) then
         WolfSSL.Free_RSA (Key => RSA_Encrypt_Key);
      end if;

      if WolfSSL.Is_Valid (RSA_Decrypt_Key) then
         WolfSSL.Free_RSA (Key => RSA_Decrypt_Key);
      end if;

      if WolfSSL.Is_Valid (RNG) then
         WolfSSL.Free_RNG (Key => RNG);
      end if;
   end Cleanup;
begin
   WolfSSL.Create_RNG (Key    => RNG,
                       Result => R);
   if R /= 0 then
      Put ("Attaining RNG key instance failed");
      New_Line;
      Cleanup;
      return;
   end if;

   WolfSSL.Create_RSA (Key    => RSA_Encrypt_Key,
                       Result => R);
   if R /= 0 then
      Put ("Attaining RSA key instance failed");
      New_Line;
      Cleanup;
      return;
   end if;

   WolfSSL.Rsa_Set_RNG (Key    => RSA_Encrypt_Key,
                        RNG    => RNG,
                        Result => R);
   if R /= 0 then
      Put ("Associating RSA key with random number generator failed");
      New_Line;
      Cleanup;
      return;
   end if;

   Index := Client_Private_Key_2048'First;
   WolfSSL.Rsa_Private_Key_Decode (Input  => Client_Private_Key_2048,
                                   Index  => Index,
                                   Key    => RSA_Encrypt_Key,
                                   Size   => Client_Private_Key_2048'Length,
                                   Result => R);
   if R /= 0 then
      Put ("Loading private RSA key failed with error code ");
      Put (R);
      New_Line;
      Cleanup;
      return;
   end if;

   WolfSSL.Rsa_SSL_Sign (Input  => Original_AES_Key,
                         Output => Digital_Signature_Of_AES_Key,
                         RSA    => RSA_Encrypt_Key,
                         RNG    => RNG,
                         Result => R);
   if R < 0 then
      Put ("Creating digital signature using RSA private key failed");
      Put (R);
      New_Line;
      Cleanup;
      return;
   end if;

   WolfSSL.Create_RSA (Key    => RSA_Decrypt_Key,
                       Result => R);
   if R /= 0 then
      Put ("Attaining RSA key instance failed");
      New_Line;
      Cleanup;
      return;
   end if;

   Index := Rsa_Public_key_2048'First;
   WolfSSL.Rsa_Public_Key_Decode (Input  => Rsa_Public_key_2048,
                                  Index  => Index,
                                  Key    => RSA_Decrypt_Key,
                                  Size   => Rsa_Public_key_2048'Length,
                                  Result => R);
   if R /= 0 then
      Put ("Loading public RSA key failed with DER encoded key");
      Put (R);
      New_Line;
      Cleanup;
      return;
   end if;

   WolfSSL.Rsa_SSL_Verify (Input  => Digital_Signature_Of_AES_Key,
                           Output => Decrypted_Digital_Signature,
                           RSA    => RSA_Decrypt_Key,
                           Result => R);
   if R < 0 then
      Put ("Verify digital signature failed");
      Put (R);
      New_Line;
      Cleanup;
      return;
   end if;
   Put ("Successful verification of RSA based digital signature.");
   New_Line;

   WolfSSL.RSA_Public_Encrypt (Input  => Original_AES_Key,
                               Output => Encrypted,
                               Index  => Index,
                               RSA    => RSA_Decrypt_Key,
                               RNG    => RNG,
                               Result => R);
   if R < 0 then
      Put ("Failed to encrypt the original AES key");
      Put (R);
      New_Line;
      Cleanup;
      return;
   end if;

   WolfSSL.RSA_Private_Decrypt (Input  => Encrypted (1 .. Index),
                                Output => Decrypted,
                                Index  => Index,
                                RSA    => RSA_Encrypt_Key,
                                Result => R);
   if R < 0 then
      Put ("Failed to decrypt the encrypted original AES key");
      Put (R);
      New_Line;
      Cleanup;
      return;
   end if;

   if Integer (Index) /= 32 then
      Put ("Decryption of the encrypted original AES key, wrong size");
      New_Line;
      Cleanup;
      return;
   end if;

   if Original_AES_Key = Decrypted (1 .. 32) then
      Put ("Successfully encrypted and decrypted using RSA.");
      New_Line;
   else
      Put ("Failed to encrypt and decrypt original AES key.");
      New_Line;
   end if;

   Cleanup;
end Rsa_Verify_Main;
