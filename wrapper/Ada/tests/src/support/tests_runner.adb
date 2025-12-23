with AUnit.Reporter.Text;
with AUnit.Run;

with Tests_Root_Suite;

package body Tests_Runner is

   --  Instantiate the generic AUnit runner at library level so it does not
   --  capture any local objects and remains fully static.
   procedure Runner is new AUnit.Run.Test_Runner (Tests_Root_Suite.Suite);

   procedure Run (Reporter : in out AUnit.Reporter.Text.Text_Reporter) is
   begin
      Runner (Reporter);
   end Run;

end Tests_Runner;