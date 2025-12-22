with AUnit.Test_Suites;

package SHA256_Bindings_Tests is

   --  Tests for the WolfSSL SHA256 Ada bindings:
   --    - Create_SHA256
   --    - Update_SHA256
   --    - Finalize_SHA256
   --
   --  This package follows AUnit's "Test_Caller" model (not Test_Cases with
   --  Registration) to avoid depending on optional child units and to keep the
   --  boilerplate small.
   --
   --  Suite returns a suite containing all SHA256-related tests.

   function Suite return AUnit.Test_Suites.Access_Test_Suite;

end SHA256_Bindings_Tests;