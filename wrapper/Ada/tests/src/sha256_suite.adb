with AUnit.Test_Suites;

with SHA256_Bindings_Tests;

package body SHA256_Suite is

   --  Statically allocated (library-level) suite object.
   Root : aliased AUnit.Test_Suites.Test_Suite;

   --  Must be declared before the package body's `begin` in standard Ada.
   function Suite return AUnit.Test_Suites.Access_Test_Suite is
   begin
      return Root'Access;
   end Suite;

begin
   --  Register SHA256-related test suites here (performed at elaboration time).
   AUnit.Test_Suites.Add_Test (Root'Access, SHA256_Bindings_Tests.Suite);

end SHA256_Suite;