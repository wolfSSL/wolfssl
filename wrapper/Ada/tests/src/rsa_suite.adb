with AUnit.Test_Suites;

with RSA_Verify_Bindings_Tests;

package body RSA_Suite is

   --  Statically allocated (library-level) suite object.
   --  Built once at elaboration time (no guard needed).
   Root : aliased AUnit.Test_Suites.Test_Suite;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
   begin
      return Root'Access;
   end Suite;

begin
   --  Register RSA-related test suites here.
   AUnit.Test_Suites.Add_Test (Root'Access, RSA_Verify_Bindings_Tests.Suite);

end RSA_Suite;