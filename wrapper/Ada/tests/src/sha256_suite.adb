with AUnit.Test_Suites;

with SHA256_Bindings_Tests;

package body SHA256_Suite is

   --  Statically allocated (library-level) suite object.
   --  This avoids heap allocation and satisfies Ada accessibility rules when
   --  returning an Access_Test_Suite.
   Root  : aliased AUnit.Test_Suites.Test_Suite;
   Built : Boolean := False;

   procedure Build_Once is
   begin
      if Built then
         return;
      end if;

      --  Register SHA256-related test suites here.
      AUnit.Test_Suites.Add_Test (Root'Access, SHA256_Bindings_Tests.Suite);

      Built := True;
   end Build_Once;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
   begin
      Build_Once;
      return Root'Access;
   end Suite;

end SHA256_Suite;