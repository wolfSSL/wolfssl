with AUnit.Assertions;
with AUnit.Test_Caller;

with WolfSSL;

package body SHA256_Bindings_Tests is

   ----------------------------------------------------------------------------
   --  Helpers
   ----------------------------------------------------------------------------

   procedure Assert_Text_Matches_Hash
     (Hash : WolfSSL.SHA256_Hash;
      Text : WolfSSL.SHA256_As_String;
      Msg  : String);

   procedure Compute_SHA256
     (Input  : WolfSSL.Byte_Array;
      Hash   : out WolfSSL.SHA256_Hash;
      Text   : out WolfSSL.SHA256_As_String;
      Result : out Integer);

   procedure Assert_Text_Matches_Hash
     (Hash : WolfSSL.SHA256_Hash;
      Text : WolfSSL.SHA256_As_String;
      Msg  : String)
   is
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
                  Msg & ": invalid hex character '" & C & "'");
               return 0;
         end case;
      end Hex_Value;

      I           : Positive;
      Hi          : Natural;
      Lo          : Natural;
      Byte_As_Int : Natural;
   begin
      AUnit.Assertions.Assert
        (Text'Length = 64,
         Msg & ": expected 64 hex chars, got" & Integer'Image (Text'Length));

      for Index in Positive range 1 .. 32 loop
         I := 2 * (Index - 1) + 1;
         Hi := Hex_Value (Text (I));
         Lo := Hex_Value (Text (I + 1));

         Byte_As_Int := 16 * Hi + Lo;

         --  SHA256_Hash is a Byte_Array backed by `Interfaces.C.char_array`.
         --  Avoid a direct `Interfaces.C` dependency here by using the binding's
         --  own aliases (`Byte_Type`, `Byte_Index`) for indexing and conversion.
         AUnit.Assertions.Assert
           (Byte_As_Int =
              WolfSSL.Byte_Type'Pos (Hash (WolfSSL.Byte_Index (Index))),
            Msg & ": Text/Hash mismatch at byte" &
              Integer'Image (Index));
      end loop;

      --  `Finalize_SHA256` generates uppercase hex, validate that expectation.
      for J in Text'Range loop
         declare
            C : constant Character := Text (J);
         begin
            if C in '0' .. '9' or else C in 'A' .. 'F' then
               null;
            else
               AUnit.Assertions.Assert
                 (False,
                  Msg & ": expected uppercase hex at pos" &
                    Integer'Image (J));
            end if;
         end;
      end loop;
   end Assert_Text_Matches_Hash;

   procedure Compute_SHA256
     (Input  : WolfSSL.Byte_Array;
      Hash   : out WolfSSL.SHA256_Hash;
      Text   : out WolfSSL.SHA256_As_String;
      Result : out Integer)
   is
      SHA256 : WolfSSL.SHA256_Type;
      R      : Integer;
   begin
      --  Follow the example in `sha256_main.adb` (Index => 1).
      WolfSSL.Create_SHA256 (Index => 1, SHA256 => SHA256, Result => R);
      if R /= 0 then
         Result := R;
         return;
      end if;

      WolfSSL.Update_SHA256 (SHA256 => SHA256, Byte => Input, Result => R);
      if R /= 0 then
         Result := R;
         return;
      end if;

      WolfSSL.Finalize_SHA256
        (SHA256 => SHA256,
         Hash   => Hash,
         Text   => Text,
         Result => R);

      Result := R;
   end Compute_SHA256;

   ----------------------------------------------------------------------------
   --  Tests
   ----------------------------------------------------------------------------

   procedure Test_SHA256_Asdf_Known_Vector (F : in out Fixture) is
      pragma Unreferenced (F);

      Hash : WolfSSL.SHA256_Hash;
      Text : WolfSSL.SHA256_As_String;
      R    : Integer;

      Input : constant WolfSSL.Byte_Array :=
        (1 => 'a',
         2 => 's',
         3 => 'd',
         4 => 'f');

      Expected_Text : constant WolfSSL.SHA256_As_String :=
        "F0E4C2F76C58916EC258F246851BEA091D14D4247A2FC3E18694461B1816E13B";
   begin
      Compute_SHA256 (Input => Input, Hash => Hash, Text => Text, Result => R);

      AUnit.Assertions.Assert
        (R = 0,
         "SHA256('asdf') bindings should succeed, Result =" &
           Integer'Image (R));

      AUnit.Assertions.Assert
        (Text = Expected_Text,
         "SHA256('asdf') hex mismatch. Got: " & Text);

      Assert_Text_Matches_Hash
        (Hash => Hash, Text => Text, Msg => "SHA256('asdf')");
   end Test_SHA256_Asdf_Known_Vector;

   procedure Test_SHA256_Empty_Message (F : in out Fixture) is
      pragma Unreferenced (F);

      Hash : WolfSSL.SHA256_Hash;
      Text : WolfSSL.SHA256_As_String;
      R    : Integer;

      --  If this doesn't compile depending on how `Byte_Array` is declared,
      --  rework this test to produce an empty input safely for that declaration.
      Empty : constant WolfSSL.Byte_Array := (1 .. 0 => <>);

      Expected_Text : constant WolfSSL.SHA256_As_String :=
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
   begin
      Compute_SHA256 (Input => Empty, Hash => Hash, Text => Text, Result => R);

      AUnit.Assertions.Assert
        (R = 0,
         "SHA256('') bindings should succeed, Result =" &
           Integer'Image (R));

      AUnit.Assertions.Assert
        (Text = Expected_Text,
         "SHA256('') hex mismatch. Got: " & Text);

      Assert_Text_Matches_Hash
        (Hash => Hash,
         Text => Text,
         Msg  => "SHA256('')");
   end Test_SHA256_Empty_Message;

   ----------------------------------------------------------------------------
   --  Statically allocated suite object; register tests at elaboration time
   ----------------------------------------------------------------------------

   package Caller is new AUnit.Test_Caller (Fixture);

   Suite_Object : aliased AUnit.Test_Suites.Test_Suite;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
   begin
      return Suite_Object'Access;
   end Suite;

begin
   --  Register SHA256-related tests once at elaboration time.
   --  Note: Caller.Create returns an access value; AUnit may still allocate
   --  the test-case objects internally. This keeps the suite itself static.
   AUnit.Test_Suites.Add_Test
     (Suite_Object'Access,
      Caller.Create
        (Name => "SHA256('asdf') produces expected hash",
         Test => Test_SHA256_Asdf_Known_Vector'Access));

   AUnit.Test_Suites.Add_Test
     (Suite_Object'Access,
      Caller.Create
        (Name => "SHA256('') produces expected hash",
         Test => Test_SHA256_Empty_Message'Access));

end SHA256_Bindings_Tests;
