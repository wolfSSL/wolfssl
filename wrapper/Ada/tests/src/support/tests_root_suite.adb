with AUnit.Test_Suites;

with SHA256_Suite;
with RSA_Suite;
with AES_Suite;

package body Tests_Root_Suite is

   --  Library-level object (static storage) so returning its access is legal
   --  (no dangling pointer / accessibility issues).
   Root : aliased AUnit.Test_Suites.Test_Suite;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
   begin
      return Root'Access;
   end Suite;

begin
   --  Compose the root suite at elaboration time.
   --  Note: all declarations (including Suite) must appear before this begin.
   AUnit.Test_Suites.Add_Test (Root'Access, SHA256_Suite.Suite);
   AUnit.Test_Suites.Add_Test (Root'Access, RSA_Suite.Suite);
   AUnit.Test_Suites.Add_Test (Root'Access, AES_Suite.Suite);

end Tests_Root_Suite;