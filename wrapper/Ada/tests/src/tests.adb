with AUnit.Reporter.Text;
with AUnit.Run;

--  Minimal AUnit runner.
--  AUnit uses a generic test runner instantiated with your suite function.
with SHA256_Suite;

procedure Tests is
   procedure Runner is new AUnit.Run.Test_Runner (SHA256_Suite.Suite);

   Reporter : AUnit.Reporter.Text.Text_Reporter;
begin
   Runner (Reporter);
end Tests;