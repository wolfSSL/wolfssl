with AUnit.Assertions;
with AUnit.Test_Caller;
with AUnit.Test_Fixtures;

with WolfSSL;

package body RSA_Verify_Bindings_Tests is

   type Fixture is new AUnit.Test_Fixtures.Test_Fixture with null record;

   type Unsigned_8 is mod 2 ** 8;

   function To_C (Value : Unsigned_8) return WolfSSL.Byte_Type is
   begin
      return WolfSSL.Byte_Type'Val (Value);
   end To_C;

   use type WolfSSL.Byte_Array;
   use type WolfSSL.Byte_Index;

   --  RSA public key to verify with (DER) - copied from rsa_verify_main.adb.
   Rsa_Public_Key_2048 : constant WolfSSL.Byte_Array :=
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

   --  Private key (DER) - copied from rsa_verify_main.adb.
   --
   --  Note: This is long, but keeping it embedded avoids any assumptions about
   --  external files and precisely matches the example.
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

   Original_AES_Key : constant WolfSSL.Byte_Array (1 .. 32) :=
     "Thisismyfakeaeskeythatis32bytes!";

   procedure Test_RSA_Sign_Verify_And_Encrypt_Decrypt (F : in out Fixture) is
      pragma Unreferenced (F);

      RNG             : WolfSSL.RNG_Type;
      RSA_Encrypt_Key : WolfSSL.RSA_Key_Type;
      RSA_Decrypt_Key : WolfSSL.RSA_Key_Type;

      Digital_Signature_Of_AES_Key : WolfSSL.Byte_Array (1 .. 256);
      Decrypted_Digital_Signature  : WolfSSL.Byte_Array (1 .. 256);

      Encrypted  : WolfSSL.Byte_Array (1 .. 1_024);
      Decrypted  : WolfSSL.Byte_Array (1 .. 1_024);

      Index : WolfSSL.Byte_Index;
      R     : Integer;
   begin
      WolfSSL.Create_RNG (Key    => RNG,
                          Result => R);
      AUnit.Assertions.Assert (R = 0, "Create_RNG failed, Result =" &
                                Integer'Image (R));

      WolfSSL.Create_RSA (Key    => RSA_Encrypt_Key,
                          Result => R);
      AUnit.Assertions.Assert (R = 0, "Create_RSA (private) failed, Result =" &
                                Integer'Image (R));

      WolfSSL.Rsa_Set_RNG (Key    => RSA_Encrypt_Key,
                           RNG    => RNG,
                           Result => R);
      AUnit.Assertions.Assert (R = 0, "Rsa_Set_RNG failed, Result =" &
                                Integer'Image (R));

      Index := Client_Private_Key_2048'First;
      WolfSSL.Rsa_Private_Key_Decode (Input  => Client_Private_Key_2048,
                                      Index  => Index,
                                      Key    => RSA_Encrypt_Key,
                                      Size   => Client_Private_Key_2048'Length,
                                      Result => R);
      AUnit.Assertions.Assert (R = 0, "Rsa_Private_Key_Decode failed, Result =" &
                                Integer'Image (R));

      WolfSSL.Rsa_SSL_Sign (Input  => Original_AES_Key,
                            Output => Digital_Signature_Of_AES_Key,
                            RSA    => RSA_Encrypt_Key,
                            RNG    => RNG,
                            Result => R);
      AUnit.Assertions.Assert (R > 0,
                              "Rsa_SSL_Sign failed, Result =" &
                                Integer'Image (R));

      WolfSSL.Create_RSA (Key    => RSA_Decrypt_Key,
                          Result => R);
      AUnit.Assertions.Assert (R = 0, "Create_RSA (public) failed, Result =" &
                                Integer'Image (R));

      Index := Rsa_Public_Key_2048'First;
      WolfSSL.Rsa_Public_Key_Decode (Input  => Rsa_Public_Key_2048,
                                     Index  => Index,
                                     Key    => RSA_Decrypt_Key,
                                     Size  => Rsa_Public_Key_2048'Length,
                                     Result => R);
      AUnit.Assertions.Assert (R = 0, "Rsa_Public_Key_Decode failed, Result =" &
                                Integer'Image (R));

      WolfSSL.Rsa_SSL_Verify (Input  => Digital_Signature_Of_AES_Key,
                              Output => Decrypted_Digital_Signature,
                              RSA    => RSA_Decrypt_Key,
                              Result => R);
      AUnit.Assertions.Assert (R > 0,
                              "Rsa_SSL_Verify failed, Result =" &
                                Integer'Image (R));

      --  Basic sanity: verify decrypted signature begins with the plaintext input.
      --  The example does not explicitly check this; it only checks success.
      AUnit.Assertions.Assert
        (Decrypted_Digital_Signature (1 .. Original_AES_Key'Length) =
           Original_AES_Key,
         "Verified signature payload does not match original input");

      WolfSSL.RSA_Public_Encrypt (Input  => Original_AES_Key,
                                  Output => Encrypted,
                                  Index  => Index,
                                  RSA    => RSA_Decrypt_Key,
                                  RNG    => RNG,
                                  Result => R);
      AUnit.Assertions.Assert (R > 0,
                              "RSA_Public_Encrypt failed, Result =" &
                                Integer'Image (R));
      AUnit.Assertions.Assert (Index > 0,
                              "RSA_Public_Encrypt returned Index = 0");

      WolfSSL.RSA_Private_Decrypt (Input  => Encrypted (1 .. Index),
                                   Output => Decrypted,
                                   Index  => Index,
                                   RSA    => RSA_Encrypt_Key,
                                   Result => R);
      AUnit.Assertions.Assert (R > 0,
                              "RSA_Private_Decrypt failed, Result =" &
                                Integer'Image (R));

      AUnit.Assertions.Assert (Integer (Index) = 32,
                              "RSA_Private_Decrypt output length mismatch, got" &
                                Integer'Image (Integer (Index)));

      AUnit.Assertions.Assert (Decrypted (1 .. 32) = Original_AES_Key,
                              "RSA decrypt result does not equal original key");

      --  Ensure RSA key resources are released (RSA is now dynamically allocated).
      WolfSSL.Free_RSA (Key => RSA_Encrypt_Key);
      WolfSSL.Free_RSA (Key => RSA_Decrypt_Key);

      --  Ensure RNG resources are released (RNG is now dynamically allocated).
      --  Must be done after all operations that use RNG / depend on it.
      WolfSSL.Free_RNG (Key => RNG);
   end Test_RSA_Sign_Verify_And_Encrypt_Decrypt;

   package Caller is new AUnit.Test_Caller (Fixture);

   Suite_Object : aliased AUnit.Test_Suites.Test_Suite;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
   begin
      return Suite_Object'Access;
   end Suite;

begin
   --  Register RSA tests once at elaboration time.
   AUnit.Test_Suites.Add_Test
     (Suite_Object'Access,
      Caller.Create
        (Name => "RSA sign/verify and encrypt/decrypt (rsa_verify_main)",
         Test => Test_RSA_Sign_Verify_And_Encrypt_Decrypt'Access));

end RSA_Verify_Bindings_Tests;
