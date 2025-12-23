with AUnit.Reporter.Text;

with Tests_Runner;

procedure Tests is
   Reporter : AUnit.Reporter.Text.Text_Reporter;
begin
   Tests_Runner.Run (Reporter);
end Tests;