with AUnit.Assertions;

with WolfSSL;

package body Test_Support is

   ----------------------------------------------------------------------------
   -- Assertions
   ----------------------------------------------------------------------------

   procedure Assert_Success (Result : Integer; What : String) is
   begin
      AUnit.Assertions.Assert
        (Result = 0,
         What & " failed, Result =" & Integer'Image (Result));
   end Assert_Success;

   ----------------------------------------------------------------------------
   -- Data helpers
   ----------------------------------------------------------------------------

   function Bytes (S : String) return WolfSSL.Byte_Array is
      --  WolfSSL.Byte_Array is Interfaces.C.char_array indexed by
      --  WolfSSL.Byte_Index (size_t). Avoid doing arithmetic directly on that
      --  index type; instead, use Natural for arithmetic and convert at the
      --  point of indexing.
      Last_N : constant Natural := (if S'Length = 0 then 0 else S'Length - 1);
      B      : WolfSSL.Byte_Array (0 .. WolfSSL.Byte_Index (Last_N));
      N      : Natural := 0;
   begin
      for C of S loop
         B (WolfSSL.Byte_Index (N)) :=
           WolfSSL.Byte_Type'Val (Character'Pos (C));
         N := N + 1;
      end loop;
      return B;
   end Bytes;

   function Hex_Value (C : Character) return Natural is
   begin
      case C is
         when '0' .. '9' =>
            return Character'Pos (C) - Character'Pos ('0');
         when 'A' .. 'F' =>
            return 10 + (Character'Pos (C) - Character'Pos ('A'));
         when 'a' .. 'f' =>
            return 10 + (Character'Pos (C) - Character'Pos ('a'));
         when others =>
            AUnit.Assertions.Assert
              (False,
               "invalid hex character '" & C & "'");
            return 0;
      end case;
   end Hex_Value;

   function Hex_Bytes (Hex : String) return WolfSSL.Byte_Array is
      Len : constant Natural := Hex'Length;
   begin
      AUnit.Assertions.Assert
        (Len mod 2 = 0,
         "hex string length must be even, got" & Integer'Image (Len));

      declare
         N      : constant Natural := Len / 2;
         Last_N : constant Natural := (if N = 0 then 0 else N - 1);
         B      : WolfSSL.Byte_Array (0 .. WolfSSL.Byte_Index (Last_N));
         Hi     : Natural;
         Lo     : Natural;
         J      : Natural := 0;
      begin
         for K in 0 .. N - 1 loop
            J := 2 * K;
            Hi := Hex_Value (Hex (Hex'First + J));
            Lo := Hex_Value (Hex (Hex'First + J + 1));
            B (WolfSSL.Byte_Index (K)) :=
              WolfSSL.Byte_Type'Val (16 * Hi + Lo);
         end loop;
         return B;
      end;
   end Hex_Bytes;

   function SHA256_Text (Hex : String) return WolfSSL.SHA256_As_String is
      T : WolfSSL.SHA256_As_String;
      I : Natural := 0;
   begin
      AUnit.Assertions.Assert
        (Hex'Length = T'Length,
         "SHA256 hex must be 64 characters, got" &
           Integer'Image (Hex'Length));

      for C of Hex loop
         I := I + 1;
         T (T'First + (I - 1)) := C;
      end loop;

      return T;
   end SHA256_Text;

end Test_Support;