with SHA256_Suite;
with RSA_Suite;
with AES_Suite;

package body Tests_Root_Suite is

   --  Library-level object (static storage) so returning its access is legal
   --  (no dangling pointer / accessibility issues).
   Root : aliased AUnit.Test_Suites.Test_Suite;

   Built : Boolean := False;

   procedure Build_Once is
   begin
      if Built then
         return;
      end if;

      --  Compose the root suite from sub-suites.
      AUnit.Test_Suites.Add_Test (Root'Access, SHA256_Suite.Suite);
      AUnit.Test_Suites.Add_Test (Root'Access, RSA_Suite.Suite);
      AUnit.Test_Suites.Add_Test (Root'Access, AES_Suite.Suite);

      Built := True;
   end Build_Once;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
   begin
      Build_Once;
      return Root'Access;
   end Suite;

end Tests_Root_Suite;
