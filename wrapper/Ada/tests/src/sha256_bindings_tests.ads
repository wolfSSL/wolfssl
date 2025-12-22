with AUnit.Test_Fixtures;
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

   type Fixture is new AUnit.Test_Fixtures.Test_Fixture with null record;

   procedure Test_SHA256_Asdf_Known_Vector (F : in out Fixture);
   procedure Test_SHA256_Empty_Message     (F : in out Fixture);

   function Suite return AUnit.Test_Suites.Access_Test_Suite;

end SHA256_Bindings_Tests;