with AES_Bindings_Tests;
with RSA_Verify_Bindings_Tests;
with SHA256_Bindings_Tests;

package body Tests_Root_Suite is

   --  Statically allocated (library-level) suite object.
   --  Returning Root'Access is safe (no dangling pointer / accessibility issues),
   --  and avoids heap allocation (so Valgrind stays clean).
   Root : aliased AUnit.Test_Suites.Test_Suite;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
   begin
      return Root'Access;
   end Suite;

begin
   --  Register all binding test suites at elaboration time.
   AUnit.Test_Suites.Add_Test (Root'Access, SHA256_Bindings_Tests.Suite);
   AUnit.Test_Suites.Add_Test (Root'Access, RSA_Verify_Bindings_Tests.Suite);
   AUnit.Test_Suites.Add_Test (Root'Access, AES_Bindings_Tests.Suite);

end Tests_Root_Suite;