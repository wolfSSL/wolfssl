with AUnit.Reporter.Text;

--  Dedicated AUnit runner.
--
--  This unit exists so the generic instantiation of AUnit's test runner can be
--  placed at library level (static), rather than inside `procedure Tests`.
--
--  The body is expected to instantiate `AUnit.Run.Test_Runner` with the root
--  suite function (e.g. `Tests_Root_Suite.Suite`) and expose a simple `Run`
--  wrapper.

package Tests_Runner is

   procedure Run (Reporter : in out AUnit.Reporter.Text.Text_Reporter);

end Tests_Runner;