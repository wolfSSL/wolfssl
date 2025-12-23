with AUnit.Test_Suites;

--  Library-level root suite holder.
--
--  Purpose:
--    - Provide a statically-allocated (non-heap) top-level suite object.
--    - Return an Access_Test_Suite that safely designates a library-level object
--      (to satisfy Ada accessibility rules without Unrestricted_Access).
--
--  The body is responsible for populating the suite exactly once (typically at
--  elaboration time).

package Tests_Root_Suite is

   --  Return the root test suite (statically allocated, library-level).
   function Suite return AUnit.Test_Suites.Access_Test_Suite;

end Tests_Root_Suite;