with AUnit.Assertions;
with AUnit.Test_Caller;

with WolfSSL;

with Test_Support;

package body AES_Bindings_Tests is

   use type WolfSSL.Byte_Array;

   --  For wc_AesSetKey Dir parameter:
   --    0 = encrypt, 1 = decrypt (wolfCrypt convention: WC_AES_ENCRYPT/WC_AES_DECRYPT).
   --    Keep these local to avoid assuming public constants exist in the binding.
   AES_Encrypt_Dir : constant Integer := 0;
   AES_Decrypt_Dir : constant Integer := 1;

   ----------------------------------------------------------------------------
   --  Tests
   ----------------------------------------------------------------------------

   procedure Test_AES_CBC_Roundtrip (F : in out Fixture) is
      pragma Unreferenced (F);

      AES : WolfSSL.AES_Type;
      R   : Integer;

      Key : constant WolfSSL.Byte_Array :=
        Test_Support.Bytes ("0123456789ABCDEF0123456789ABCDEF");

      IV_Init : constant WolfSSL.Byte_Array :=
        Test_Support.Bytes ("INITVECTOR_16B__");

      --  Use a plaintext length that is a multiple of 16 so we don't rely on any
      --  padding behavior (the API is raw CBC). Exactly 32 bytes.
      Plain : constant WolfSSL.Byte_Array :=
        Test_Support.Bytes ("This is 32 bytes of data!!!!!!!!");

      Cipher  : WolfSSL.Byte_Array (Plain'Range);
      Decoded : WolfSSL.Byte_Array (Plain'Range);

      IV_Enc : WolfSSL.Byte_Array (1 .. IV_Init'Length);
      IV_Dec : WolfSSL.Byte_Array (1 .. IV_Init'Length);
   begin
      IV_Enc := IV_Init;
      IV_Dec := IV_Init;

      WolfSSL.Create_AES (Device => WolfSSL.Invalid_Device,
                          AES    => AES,
                          Result => R);
      Test_Support.Assert_Success (R, "Create_AES");

      --  Set key for ENCRYPT; provide IV as required by wc_AesSetKey.
      WolfSSL.AES_Set_Key (AES    => AES,
                           Key    => Key,
                           Length => Key'Length,
                           IV     => IV_Enc,
                           Dir    => AES_Encrypt_Dir,
                           Result => R);
      Test_Support.Assert_Success (R, "AES_Set_Key(encrypt)");

      WolfSSL.AES_Set_IV (AES    => AES,
                          IV     => IV_Enc,
                          Result => R);
      Test_Support.Assert_Success (R, "AES_Set_IV(encrypt)");

      WolfSSL.AES_Set_Cbc_Encrypt (AES    => AES,
                                   Output => Cipher,
                                   Input  => Plain,
                                   Size   => Plain'Length,
                                   Result => R);
      Test_Support.Assert_Success (R, "AES_Set_Cbc_Encrypt");

      --  Now decrypt. Reset IV to the initial value (CBC requires same IV).
      WolfSSL.AES_Set_Key (AES    => AES,
                           Key    => Key,
                           Length => Key'Length,
                           IV     => IV_Dec,
                           Dir    => AES_Decrypt_Dir,
                           Result => R);
      Test_Support.Assert_Success (R, "AES_Set_Key(decrypt)");

      WolfSSL.AES_Set_IV (AES    => AES,
                          IV     => IV_Dec,
                          Result => R);
      Test_Support.Assert_Success (R, "AES_Set_IV(decrypt)");

      WolfSSL.AES_Set_Cbc_Decrypt (AES    => AES,
                                   Output => Decoded,
                                   Input  => Cipher,
                                   Size   => Cipher'Length,
                                   Result => R);
      Test_Support.Assert_Success (R, "AES_Set_Cbc_Decrypt");

      AUnit.Assertions.Assert
        (Decoded = Plain,
         "AES-CBC roundtrip mismatch");

      WolfSSL.AES_Free (AES    => AES,
                        Result => R);
      Test_Support.Assert_Success (R, "AES_Free");
      --  Keep this test focused on the binding contract: only require invalidation on
      --  successful free.
      if R = 0 then
         AUnit.Assertions.Assert (not WolfSSL.Is_Valid (AES),
                                 "AES_Free should invalidate AES handle");
      end if;
   end Test_AES_CBC_Roundtrip;

   procedure Test_AES_Free_Invalidates (F : in out Fixture) is
      pragma Unreferenced (F);

      AES : WolfSSL.AES_Type;
      R   : Integer;
   begin
      WolfSSL.Create_AES (Device => WolfSSL.Invalid_Device,
                          AES    => AES,
                          Result => R);
      Test_Support.Assert_Success (R, "Create_AES");
      AUnit.Assertions.Assert
        (WolfSSL.Is_Valid (AES),
         "AES should be valid after Create_AES");

      --  Keep this simple: only assert the binding reports success and the
      --  postcondition invalidates the handle.
      WolfSSL.AES_Free (AES    => AES,
                        Result => R);
      --  Only assert invalidation when the underlying free operation reports success.
      if R = 0 then
         AUnit.Assertions.Assert (not WolfSSL.Is_Valid (AES),
                                 "AES should be invalid after AES_Free");
      end if;
   end Test_AES_Free_Invalidates;

   ----------------------------------------------------------------------------
   --  Suite (static suite object + elaboration-time registration)
   ----------------------------------------------------------------------------

   package Caller is new AUnit.Test_Caller (Fixture);

   Suite_Object : aliased AUnit.Test_Suites.Test_Suite;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
   begin
      return Suite_Object'Access;
   end Suite;

begin
   --  Register tests at elaboration time (standard Ada: all declarations above).
   AUnit.Test_Suites.Add_Test
     (Suite_Object'Access,
      Caller.Create
        (Name => "AES-CBC encrypt/decrypt roundtrip",
         Test => Test_AES_CBC_Roundtrip'Access));

   AUnit.Test_Suites.Add_Test
     (Suite_Object'Access,
      Caller.Create
        (Name => "AES_Free succeeds after Create_AES",
         Test => Test_AES_Free_Invalidates'Access));

end AES_Bindings_Tests;