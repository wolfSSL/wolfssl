with AUnit.Reporter.Text;
with AUnit.Run;
with AUnit.Test_Suites;

--  Minimal AUnit runner.
--  AUnit uses a generic test runner instantiated with your suite function.
with SHA256_Suite;
with RSA_Suite;

procedure Tests is
   function Suite return AUnit.Test_Suites.Access_Test_Suite;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      S : constant AUnit.Test_Suites.Access_Test_Suite :=
        new AUnit.Test_Suites.Test_Suite;
   begin
      AUnit.Test_Suites.Add_Test (S, SHA256_Suite.Suite);
      AUnit.Test_Suites.Add_Test (S, RSA_Suite.Suite);
      return S;
   end Suite;

   procedure Runner is new AUnit.Run.Test_Runner (Suite);

   Reporter : AUnit.Reporter.Text.Text_Reporter;
begin
   Runner (Reporter);
end Tests;