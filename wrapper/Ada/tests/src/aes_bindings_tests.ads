with AUnit.Test_Fixtures;
with AUnit.Test_Suites;

package AES_Bindings_Tests is

   --  Minimal tests for the WolfSSL AES Ada bindings.
   --
   --  Goal: keep it simple and exercise the basic CBC encrypt/decrypt path:
   --    - Create_AES
   --    - AES_Set_Key
   --    - AES_Set_IV
   --    - AES_Set_Cbc_Encrypt
   --    - AES_Set_Cbc_Decrypt
   --    - AES_Free
   --
   --  Tests are designed after `aes_verify_main.adb` and the API contracts in
   --  `wolfssl.ads`. We avoid making assumptions about padding: the test uses
   --  a plaintext size that is a multiple of 16 bytes (AES block size).

   type Fixture is new AUnit.Test_Fixtures.Test_Fixture with null record;

   --  Encrypt known plaintext with AES-CBC and then decrypt it; expect round-trip.
   procedure Test_AES_CBC_Roundtrip (F : in out Fixture);

   --  Ensure AES_Free succeeds and invalidates the handle.
   procedure Test_AES_Free_Invalidates (F : in out Fixture);

   function Suite return AUnit.Test_Suites.Access_Test_Suite;

end AES_Bindings_Tests;
