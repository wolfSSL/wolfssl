with AUnit.Test_Suites;

with SHA256_Bindings_Tests;

package body SHA256_Suite is

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      S : constant AUnit.Test_Suites.Access_Test_Suite :=
        new AUnit.Test_Suites.Test_Suite;
   begin
      --  Register SHA256-related test suites here.
      AUnit.Test_Suites.Add_Test (S, SHA256_Bindings_Tests.Suite);

      return S;
   end Suite;

end SHA256_Suite;