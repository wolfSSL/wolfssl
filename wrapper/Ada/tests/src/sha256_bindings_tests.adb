with AUnit.Assertions;
with AUnit.Test_Caller;

with WolfSSL;

with Test_Support;

package body SHA256_Bindings_Tests is

   ----------------------------------------------------------------------------
   --  Helpers
   ----------------------------------------------------------------------------

   procedure Compute_SHA256
     (Input  : WolfSSL.Byte_Array;
      Hash   : out WolfSSL.SHA256_Hash;
      Result : out Integer)
   is
      SHA256 : WolfSSL.SHA256_Type;
      R      : Integer;
   begin
      --  SHA256 instances are dynamically allocated; no index is required.
      WolfSSL.Create_SHA256 (SHA256 => SHA256, Result => R);
      if R /= 0 then
         Result := R;
         return;
      end if;

      WolfSSL.Update_SHA256 (SHA256 => SHA256, Byte => Input, Result => R);
      if R /= 0 then
         Result := R;
         WolfSSL.Free_SHA256 (SHA256 => SHA256);
         return;
      end if;

      WolfSSL.Finalize_SHA256
        (SHA256 => SHA256,
         Hash   => Hash,
         Result => R);

      Result := R;

      WolfSSL.Free_SHA256 (SHA256 => SHA256);
   end Compute_SHA256;

   ----------------------------------------------------------------------------
   --  Tests
   ----------------------------------------------------------------------------

   procedure Test_SHA256_Asdf_Known_Vector (F : in out Fixture) is
      pragma Unreferenced (F);

      Hash : WolfSSL.SHA256_Hash;
      R    : Integer;

      Input : constant WolfSSL.Byte_Array := Test_Support.Bytes ("asdf");

      Expected_Hash : constant WolfSSL.Byte_Array :=
        Test_Support.Hex_Bytes
          (Test_Support.SHA256_Text
             ("F0E4C2F76C58916EC258F246851BEA091D14D4247A2FC3E18694461B1816E13B"));
   begin
      Compute_SHA256 (Input => Input, Hash => Hash, Result => R);

      Test_Support.Assert_Success (R, "SHA256(asdf)");

      --  Compare the hash bytes
      declare
         use type WolfSSL.Byte_Array;
         Hash_Bytes : WolfSSL.Byte_Array (Expected_Hash'Range);
         J : WolfSSL.Byte_Index := Expected_Hash'First;
      begin
         for I in Hash'Range loop
            Hash_Bytes (J) := Hash (I);
            J := WolfSSL.Byte_Index'Succ (J);
         end loop;
         AUnit.Assertions.Assert
           (Hash_Bytes = Expected_Hash,
            "SHA256('asdf') hash mismatch");
      end;
   end Test_SHA256_Asdf_Known_Vector;

   procedure Test_SHA256_Empty_Message (F : in out Fixture) is
      pragma Unreferenced (F);

      Hash : WolfSSL.SHA256_Hash;
      R    : Integer;

      --  Represent empty input as a null range, matching the existing test style.
      Empty : constant WolfSSL.Byte_Array := (1 .. 0 => <>);

      Expected_Hash : constant WolfSSL.Byte_Array :=
        Test_Support.Hex_Bytes
          (Test_Support.SHA256_Text
             ("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"));
   begin
      Compute_SHA256 (Input => Empty, Hash => Hash, Result => R);

      Test_Support.Assert_Success (R, "SHA256(empty)");

      --  Compare the hash bytes
      declare
         use type WolfSSL.Byte_Array;
         Hash_Bytes : WolfSSL.Byte_Array (1 .. 32);
         J : WolfSSL.Byte_Index := 1;
      begin
         for I in Hash'Range loop
            Hash_Bytes (J) := Hash (I);
            J := WolfSSL.Byte_Index'Succ (J);
         end loop;
         AUnit.Assertions.Assert
           (Hash_Bytes = Expected_Hash,
            "SHA256('') hash mismatch");
      end;
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
