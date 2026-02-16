with AUnit.Reporter.Text;
with AUnit.Run;

with Tests_Root_Suite;

procedure Tests is
   Reporter : AUnit.Reporter.Text.Text_Reporter;

   --  Instantiate the generic AUnit runner with a *library-level* suite function.
   --  This avoids Ada accessibility issues (no local objects' 'Access escaping)
   --  and keeps the harness minimal.
   procedure Runner is new AUnit.Run.Test_Runner (Tests_Root_Suite.Suite);
begin
   Runner (Reporter);
end Tests;