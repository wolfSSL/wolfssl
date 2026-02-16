with AUnit.Test_Suites;

package RSA_Verify_Bindings_Tests is

   --  Tests derived from `rsa_verify_main.adb` example.
   --
   --  Intended coverage (bindings exercised):
   --    - Create_RNG
   --    - Create_RSA
   --    - Rsa_Set_RNG
   --    - Rsa_Private_Key_Decode
   --    - Rsa_Public_Key_Decode
   --    - Rsa_SSL_Sign
   --    - Rsa_SSL_Verify
   --    - RSA_Public_Encrypt
   --    - RSA_Private_Decrypt
   --
   --  The implementation will use the exact embedded DER keys and test vectors
   --  from the example to avoid assumptions about external files.

   function Suite return AUnit.Test_Suites.Access_Test_Suite;

end RSA_Verify_Bindings_Tests;