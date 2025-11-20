with WolfSSL;

package Test_Support is
   --  Small helpers to reduce test boilerplate and keep data declarations concise.

   -----------------------------------------------------------------------------
   --  Assertions
   -----------------------------------------------------------------------------

   --  Assert that a WolfSSL binding call returned success (0).
   procedure Assert_Success (Result : Integer; What : String);

   -----------------------------------------------------------------------------
   --  Data helpers
   -----------------------------------------------------------------------------

   --  Convert a String into a WolfSSL.Byte_Array, byte-for-byte.
   --  Intended for test vectors like keys/IVs/plaintext where ASCII is fine.
   function Bytes (S : String) return WolfSSL.Byte_Array;

   --  Convert a hex string (for example "0A1bFF") into a Byte_Array.
   --    - Accepts both uppercase and lowercase hex.
   --    - Requires an even number of hex characters.
   function Hex_Bytes (Hex : String) return WolfSSL.Byte_Array;

   --  Convert a hex string into a SHA256 text value.
   --  This is handy for expected SHA256 digests ("64 hex chars").
   function SHA256_Text (Hex : String) return WolfSSL.SHA256_As_String;

private
   --  Put small internal helpers in the body; keep the spec minimal.
   pragma Inline (Assert_Success);
end Test_Support;