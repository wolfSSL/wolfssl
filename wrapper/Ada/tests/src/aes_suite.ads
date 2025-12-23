with AUnit.Test_Suites;

package AES_Suite is
   --  Aggregate suite for AES binding tests.
   function Suite return AUnit.Test_Suites.Access_Test_Suite;
end AES_Suite;