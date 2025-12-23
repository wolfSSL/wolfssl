with AUnit.Test_Suites;

with AES_Bindings_Tests;

package body AES_Suite is

   --  Statically allocated (library-level) suite object.
   --  Built once at elaboration time.
   Root : aliased AUnit.Test_Suites.Test_Suite;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
   begin
      return Root'Access;
   end Suite;

begin
   --  Register AES-related test suites here.
   AUnit.Test_Suites.Add_Test (Root'Access, AES_Bindings_Tests.Suite);

end AES_Suite;