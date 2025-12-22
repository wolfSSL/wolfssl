with RSA_Verify_Bindings_Tests;

package body RSA_Suite is

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      S : constant AUnit.Test_Suites.Access_Test_Suite :=
        new AUnit.Test_Suites.Test_Suite;
   begin
      --  Register RSA-related test suites here.
      AUnit.Test_Suites.Add_Test (S, RSA_Verify_Bindings_Tests.Suite);

      return S;
   end Suite;

end RSA_Suite;