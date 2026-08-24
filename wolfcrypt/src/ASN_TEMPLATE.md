# Writing an ASN Template

wolfSSL describes each ASN.1 structure once, as a static table of `ASNItem`,
and uses that one table for both directions:

| Direction | Entry points |
|---|---|
| Decode | `GetASN_Items()` |
| Encode | `SizeASN_Items()` then `SetASN_Items()` |

The types and helpers are declared in `wolfssl/wolfcrypt/asn.h` and implemented
in `wolfcrypt/src/asn.c`. All of it is compiled only when
`WOLFSSL_ASN_TEMPLATE` is defined, which is the default (see
`wolfssl/wolfcrypt/settings.h`); the alternative implementation lives in
`wolfcrypt/src/asn_orig.c` and is selected with `WOLFSSL_ASN_ORIGINAL`
(`./configure --enable-asn=original`). A change to a template usually needs a
matching change to the original implementation, and both need building.

Only definite-length encodings are supported. A template describes DER, and
the BER it will read is BER with definite lengths - an indefinite length
(a length byte of 0x80, terminated by an end-of-contents pair) cannot be
described with a template and is not handled by the parser. Convert such an
encoding with `wc_BerToDer()` first and parse the result, as `pkcs7.c` and
`pkcs12.c` do.

Describing a structure once has a few consequences worth knowing before
writing one. The encoder and the decoder read the same table, so they cannot
drift apart the way two hand-written functions can - which is what the
original implementation has for each structure. A template is `static const`,
so it holds no state, lives in read-only memory rather than RAM, and can be
used from any number of threads at once. All the per-call state is in the
separate `ASNGetData` or `ASNSetData` array, which is why that array is
declared through macros that can put it on the stack or the heap depending on
the build.

## Adding a template

The rest of this file is reference material; this is the order to do things in.

1. Write the table - one `ASNItem` per ASN.1 item, in encoding order, with
   `depth` following the nesting. See "Template" and "Examples of ASN.1 items".
2. Write the index enum beside it, ending with
   `WOLF_ENUM_DUMMY_LAST_ELEMENT`. Repeat every `#if` from the table around the
   matching enumerator.
3. Add the `<template>_Length` define.
4. Write the decode function: `DECL_ASNGETDATA`, `CALLOC_ASNGETDATA`, register
   the binders, call `GetASN_Items()` with the right `complete`, read the
   results, `FREE_ASNGETDATA`. See "Decoding".
5. Write the encode function if the structure is produced as well as consumed:
   set the data, `noOut` anything omitted, `SizeASN_Items()`, check the output
   buffer, `SetASN_Items()`. See "Encoding".
6. Guard it all with `#ifdef WOLFSSL_ASN_TEMPLATE`, and make the matching
   change under `WOLFSSL_ASN_ORIGINAL` if that implementation handles the same
   structure.
7. Build once with `WOLFSSL_ASN_TEMPLATE_TYPE_CHECK` to type check the
   binders, and turn on `WOLFSSL_DEBUG_ASN_TEMPLATE` while it does not work.
   See "Limits, errors and debugging".
8. Add a test to `tests/api/test_asn.c` and its prototype and
   `TEST_DECL_GROUP("asn", ...)` line to `tests/api/test_asn.h`.
9. Build and run the tests both with and without `WOLFSSL_SMALL_STACK` - the
   dynamic data is declared differently in each.

## Template

A template that describes the ASN.1 items that are expected is required.

Each ASN.1 item should have a named index to make it easier to choose the item
when assigning variables or getting data.

The number of items in the template is needed too. Use a define using sizeof to
allow for modification.

```c
/* ASN template for <name of ASN.1 definition>.
 * <RFC or standard that it comes from>
 */
static const ASNItem <template>[] = {
/*  <ITEM_0> */ { <depth>, <tag>, <constructed>, <headerOnly>, <optional> },
...
};
/* Named indices for <template>. */
enum {
    <TEMPLATE>_IDX_<ITEM_0> = 0,
    <TEMPLATE>_IDX_<ITEM_1>,
    ...
    WOLF_ENUM_DUMMY_LAST_ELEMENT(<TEMPLATE>_IDX)
};
/* Number of items in <template>. */
#define <template>_Length (sizeof(<template>) / sizeof(ASNItem))
```

### Fields of an ASNItem

| Field | Meaning |
|---|---|
| `depth` | Nesting level. Items appear in encoding order and a child is one deeper than the constructed item containing it. |
| `tag` | The BER/DER tag to expect. Do **not** OR in `ASN_CONSTRUCTED` - see below. |
| `constructed` | 1 when the encoded tag is expected to have the constructed bit set. |
| `headerOnly` | 1 to stop after the header and leave the index at the content, so the items below in the template parse it. 0 to step over the whole item. |
| `optional` | 0 required, 1 optional, 2 or 3 a numbered choice (see "Numbered choice"). |

The tag is matched with the constructed bit masked off
(`(input[idx] & ~ASN_CONSTRUCTED) != asn[i].tag`), and `constructed` is checked
separately. So a constructed context-specific item is written as
`ASN_CONTEXT_SPECIFIC | 1` with `constructed` set to 1, never as
`ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1`. (The tag lists passed to
`GetASN_Choice()` are the exception and do include `ASN_CONSTRUCTED`.)

`headerOnly` reads backwards from what it does. It means "parse the header
only", which leaves the index sitting on the content, so parsing continues
*into* the item. `headerOnly` of 0 means the whole item, content included, is
stepped over.

### Conventions

- The table is named `<name>ASN` in camel case; the index enum is
  `<NAME>ASN_IDX_<ITEM>` in upper case.
- Cite the RFC or standard, and the ASN.1 definition it comes from, in the
  comment above the template.
- Quote the ASN.1 source text as a comment beside the items it describes, and
  indent each item by its depth. `x509CertASN` in `asn.c` is the reference for
  how far that is worth taking.
- **Any `#if` around an item in the table must be repeated around its
  enumerator.** Nothing checks this. An item added to the table without the
  matching enumerator silently shifts the index of every item after it, and
  the template will decode into the wrong fields.

## Translating ASN.1 notation

A lookup table for turning a specification into rows. `d` is the depth of the
item being described. Each construct is explained in full further down.

| ASN.1 | Template |
|---|---|
| `SEQUENCE { ... }` | `{ d, ASN_SEQUENCE, 1, 1, 0 }` then the members at `d + 1` |
| `SEQUENCE` whose content is not described here | `{ d, ASN_SEQUENCE, 1, 0, 0 }` - no members follow |
| `SET { ... }` | `{ d, ASN_SET, 1, 1, 0 }` then the members at `d + 1` |
| `SEQUENCE OF X` / `SET OF X` | Header item, then loop a separate template over the elements. See "SEQUENCE OF and repetition" |
| `INTEGER` | `{ d, ASN_INTEGER, 0, 0, 0 }` |
| `ENUMERATED` | `{ d, ASN_ENUMERATED, 0, 0, 0 }` |
| `BOOLEAN` | `{ d, ASN_BOOLEAN, 0, 0, 0 }` |
| `NULL` | `{ d, ASN_TAG_NULL, 0, 0, 0 }` |
| `OBJECT IDENTIFIER` | `{ d, ASN_OBJECT_ID, 0, 0, 0 }` |
| `BIT STRING` of bits | `{ d, ASN_BIT_STRING, 0, 0, 0 }` |
| `BIT STRING` wrapping DER | `{ d, ASN_BIT_STRING, 0, 1, 0 }` then the content at `d + 1` |
| `OCTET STRING` of bytes | `{ d, ASN_OCTET_STRING, 0, 0, 0 }` |
| `OCTET STRING` wrapping DER | `{ d, ASN_OCTET_STRING, 0, 1, 0 }` then the content at `d + 1` |
| `UTF8String`, `PrintableString`, `IA5String`, ... | `{ d, ASN_UTF8STRING, 0, 0, 0 }` and so on - one tag per row |
| `UTCTime` / `GeneralizedTime`, fixed | `{ d, ASN_UTC_TIME, 0, 0, 0 }` |
| `Time` (either of the two) | Two rows, same depth, `optional` of 2 or 3. See "UTCTime and GeneralizedTime" |
| `X OPTIONAL` | The row for `X` with `optional` of 1 |
| `X DEFAULT v` | The row for `X` with `optional` of 1; initialise your variable to `v`, and `noOut` it on encode when it equals `v` |
| `[n] IMPLICIT X` | The row for `X` with its tag replaced by `ASN_CONTEXT_SPECIFIC \| n` |
| `[n] EXPLICIT X` | `{ d, ASN_CONTEXT_SPECIFIC \| n, 1, 1, 0 }` then the row for `X` at `d + 1` |
| `[APPLICATION n]`, `[PRIVATE n]` | As above with `ASN_APPLICATION` or `ASN_PRIVATE` |
| `CHOICE` of different types | One row per alternative, adjacent, same depth, same `optional` of 2 or 3 |
| `CHOICE` of one type with several tags | One row, tag `0`, plus a `GetASN_Choice()` tag list at decode time |
| `ANY` | `{ d, <tag>, <cons>, 0, 0 }` if the tag is known; otherwise a tag choice list |
| Content parsed by another function | Mark the container `headerOnly` and hand its content on. See "Parsing nested content" |

`constructed` is 1 exactly when the encoded tag has the constructed bit -- every
`SEQUENCE`, `SET` and `EXPLICIT` wrapper, and an `IMPLICIT` tag on any of those.
Never OR `ASN_CONSTRUCTED` into the tag itself.

## Examples of ASN.1 items

### Sequence

This is a sequence at depth 0 and want to parse the contents.

ASN.1 description would be something like:
```
  RSASSA-PSS-params ::= SEQUENCE {
```

```c
    { 0, ASN_SEQUENCE, 1, 1, 0 },
```

To skip over the contents of the sequence, set the header to 0 indicating that
the next item to parse will be this level or higher.

```c
    { 0, ASN_SEQUENCE, 1, 0, 0 },
```

### Simple types

An INTEGER at depth 1.

ASN.1 description would be something like:
```
  prime    INTEGER,
```

```c
        { 1, ASN_INTEGER, 0, 0, 1 },
```

An OCTET_STRING at depth 1 but stop after header in order to parse contents:

ASN.1 description would be something like:
```
  digest   OCTET STRING
```

```c
        { 1, ASN_OCTET_STRING, 0, 1, 0 },
```

### Context Specific

Context specific ASN.1 items need the value associated with them.

This is a constructed ASN.1 Context Specific item of 1 that is optional.

ASN.1 description would be something like:
```
  maskGenAlgorithm  [1] MaskGeneration Default mgf1SHA1
```


```c
        { 1, ASN_CONTEXT_SPECIFIC | 1, 1, 1, 1 },
```

Context specific is one of three tag classes, and the other two are written the
same way. `ASN_CONTEXT_SPECIFIC` is 0x80, `ASN_APPLICATION` is 0x40 and
`ASN_PRIVATE` is 0xC0; a universal tag such as `ASN_INTEGER` carries no class
bits. `pivCertASN` in `asn.c` uses the other two:

```c
/* CERT */ { 1, ASN_APPLICATION | 0x13, 0, 1, 0 },
/* X509 */      { 2, ASN_APPLICATION | 0x10, 1, 0, 0 },
/* ERR  */      { 2, ASN_PRIVATE | 0x1e, 1, 0, 1 },
```

Where a number means something, give it a name rather than writing the digit -
`ASN_X509_CERT_VERSION`, `ASN_ECC_PUBKEY`, `ASN_AUTHKEYID_KEYID` and the rest
of that group in `asn.h` are exactly this, and templates read far better for
it.

#### IMPLICIT and EXPLICIT tagging

An IMPLICIT tag replaces the tag of the underlying type, so it is one item:

```
  keyIdentifier  [0] IMPLICIT OCTET STRING
```

```c
        { 1, ASN_CONTEXT_SPECIFIC | 0, 0, 0, 1 },
```

An EXPLICIT tag wraps the underlying type, so it is two items: a constructed
context specific item with `headerOnly` set, and the real item one depth
further in.

```
  version  [0] EXPLICIT Version DEFAULT v1
  Version ::= INTEGER
```

```c
        { 1, ASN_CONTEXT_SPECIFIC | 0, 1, 1, 1 },
            { 2, ASN_INTEGER, 0, 0, 0 },
```

### Optional items

An optional boolean (like criticality of a certificate extension):

ASN.1 description would be something like:
```
  critical    BOOLEAN DEFAULT FALSE,
```

```c
        { 1, ASN_BOOLEAN, 0, 0, 1 },
```

When an optional item is not present, the items below it in the template are
skipped as well, and its `tag` and `length` are left at 0. Test
`dataASN[<IDX>].tag != 0` to find out whether it was seen.

### Numbered choice

Next ASN.1 item, at depth 2, is one of multiple types:

```c
            { 2, ASN_TAG_NULL, 0, 0, 2 },
            { 2, ASN_OBJECT_ID, 0, 0, 2 },
            { 2, ASN_SEQUENCE, 1, 0, 2 },
```

Note, use the optional value to uniquely identify the choices.

Exactly one of the items sharing the number must appear, and once one matches
the rest are skipped. The items of a group must be adjacent and at the same
depth.

Only the values 2 and 3 are available: `GET_ASN_MAX_CHOICES` in `asn.c` is 2.
The "was a choice satisfied" flag is kept per number for the whole parse, so if
a template uses the same number for two separate groups, only the first group
is enforced to appear.

A numbered choice group is always required. `optional` holds the number, so
there is no room left in it to say the group as a whole may be absent, and a
group that is entered and never matched ends the parse with `ASN_PARSE_E`.

An ASN.1 `CHOICE` that is itself `OPTIONAL` therefore cannot be written this
way. The tag list form below can express it, but only where the choice is the
last thing that could appear at its depth - an item of that form reads as
absent when the enclosing constructed item has been used up, and nothing else.
Where that does not hold, lift the choice into a separate template and parse it
only when the caller has established it is there.

### Choice of tag at one position

When a single item can carry any one of a set of tags - an ASN.1 `CHOICE` of
primitives, such as `GeneralName` - use one template item and register the
permitted tags at decode time with `GetASN_Choice()`. The template's own tag is
then ignored, as is the `constructed` field.

```c
/* Tag list is terminated with 0 and does include ASN_CONSTRUCTED. */
static const byte generalNameChoice[] = {
    ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0,
    ASN_CONTEXT_SPECIFIC                   | 1,
    ...
    0
};

static const ASNItem altNameASN[] = {
    { 0, ASN_CONTEXT_SPECIFIC | 0, 0, 1, 0 }
};
```

```c
    GetASN_Choice(&dataASN[ALTNAMEASN_IDX_GN], generalNameChoice);
```

The tag that actually matched is available afterwards in
`dataASN[ALTNAMEASN_IDX_GN].tag`.

The list is checked when the item's data is stored, which has two consequences.
On a `headerOnly` item the check never runs - the parser records the tag and
descends, exactly as it ignores any other binder there - so the caller has to
reject an unwanted tag itself. `altNameASN` above is that shape. On an item
that is not `headerOnly`, a tag outside the list is a hard `ASN_PARSE_E`; it is
not treated as the item being absent. Even marked `optional`, a choice item
counts as absent only when the enclosing constructed item has been used up, not
when something unlisted is sitting there.

Because the template's tag is unused, some templates write a placeholder `0`
there instead of a real tag, to make it obvious the tag comes from the choice
list. See "String types" under "Patterns" for that form and for what else
follows from the tag not being known until run time.


# Decoding

An outline of a decoding function:

```c
#include <wolfssl/wolfcrypt/asn.h>

...

static int Decode<Something>(const byte* input, int sz, <Object Type>* <obj>)
{
    DECL_ASNGETDATA(dataASN, <template>_Length);
    int ret = 0;
    word32 idx = 0;
    /* Declare variables to parse data into. For example:
     *   byte isCA = 0;
     */

    CALLOC_ASNGETDATA(dataASN, <template>_Length, ret, <obj>->heap);

    if (ret == 0) {
        /* Set any variables to be filled in by the parser. For example:
         *  GetASN_Boolean(&dataASN[BASICCONSASN_IDX_CA], &isCA);
         *  GetASN_Int8Bit(&dataASN[BASICCONSASN_IDX_PLEN], &<obj>->pathLength);
         */

        /* Decode the ASN.1 DER. */
        ret = GetASN_Items(<template>, dataASN, <template>_Length, 1, input,
                           &idx, (word32)sz);
    }

    if (ret == 0) {
        /* Check data in variables is valid. */
    }
    if (ret == 0) {
        /* Put data in variables into object. */
    }

    FREE_ASNGETDATA(dataASN, <obj>->heap);
    return ret;
}
```

`idx` is in and out: on entry it is where to start, on return it is the index
after the data that was parsed.

The fourth argument, `complete`, says whether every constructed item entered
must be fully used up. Pass 1 when the template describes the whole encoding.
Pass 0 when parsing one element out of a larger structure - for example each
item of a `SEQUENCE OF` - otherwise trailing siblings make it fail with
`ASN_PARSE_E`.

## Declaring the dynamic data

Always use the macros, never a plain `ASNGetData` array. They have two
definitions: under `WOLFSSL_SMALL_STACK` the data is allocated from the heap,
otherwise it is a stack array. Code that declares the array directly breaks
small stack builds.

| Macro | Use |
|---|---|
| `DECL_ASNGETDATA(name, cnt)` | Declare, at the top of the function. |
| `ALLOC_ASNGETDATA(name, cnt, err, heap)` | Allocate without clearing. |
| `CALLOC_ASNGETDATA(name, cnt, err, heap)` | Allocate and clear - the usual choice. |
| `FREE_ASNGETDATA(name, heap)` | Dispose, on every return path. |

`ALLOC_` and `CALLOC_` do nothing when `err` is already non-zero, so the
`ret == 0` chain works unchanged.

`heap` is the allocation hint to use when the build is allocating - the `heap`
field of whatever object is being filled in, or NULL when there is not one. It
is ignored in a build that puts the array on the stack, but pass the same value
to `FREE_` as to `CALLOC_` regardless.

## Registering where data goes

Call these on `&dataASN[<IDX>]` before `GetASN_Items()`.

| Function | Effect |
|---|---|
| `GetASN_Int8Bit`, `GetASN_Int16Bit`, `GetASN_Int32Bit` | Store an INTEGER into a `byte`/`word16`/`word32`. |
| `GetASN_Boolean` | Store a BOOLEAN into a `byte`. |
| `GetASN_Buffer(d, data, &len)` | Copy content into a caller buffer. `len` is in as the capacity and out as the actual length; `BUFFER_E` if too small. |
| `GetASN_ExpBuffer(d, data, len)` | Require the content to equal this buffer, else `ASN_PARSE_E`. |
| `GetASN_MP`, `GetASN_MP_Inited`, `GetASN_MP_PosNeg` | Read an INTEGER into an `mp_int`. `_Inited` for one already initialised, `_PosNeg` to allow a negative value. |
| `GetASN_OID(d, oidType)` | Check the OBJECT IDENTIFIER against a class such as `oidKeyType`, `oidSigType`, `oidCertExtType`, and record its sum. |
| `GetASN_Choice(d, options)` | Accept any tag in the 0-terminated list. |

Register nothing and the item's content is simply referenced - see below.

## Getting the results out

`ASNGetData` fields that are valid after a successful parse:

| Field | Meaning |
|---|---|
| `.tag` | The tag that matched. 0 when an optional item was absent - this is the presence test. |
| `.offset` | Index in `input` of the item's tag byte. |
| `.length` | Length of the item's content. |
| `.data.ref.data`, `.data.ref.length` | Reference into `input` for an item with no binder registered, and for every `headerOnly` item. |
| `.data.oid.sum`, `.data.oid.data`, `.data.oid.length` | Set by `GetASN_OID()`. `sum` is the 32-bit id used in switch statements. |

`GetASN_GetConstRef()`, `GetASN_GetRef()` and `GetASN_OIDData()` are accessors
for the same fields.

Note that `.offset` is the index of the tag byte but `.length` is the length of
the *content*, so neither one alone describes the whole item. Rather than do
that arithmetic by hand, use the macros in `asn.h`:

| Macro | Gives |
|---|---|
| `GetASNItem_Addr(d, in)` | Pointer to the start of the item - its tag byte. |
| `GetASNItem_Length(d, in)` | Length of the whole item, tag and length bytes included. |
| `GetASNItem_DataIdx(d, in)` | Index of the item's content. |
| `GetASNItem_EndIdx(d, in)` | Index just past the item's content - where the next item starts. |
| `GetASNItem_HaveData(d)`, `GetASNItem_HaveIdx(d)` | Whether data was stored for the item. |
| `GetASNItem_UnusedBits(d)` | The unused bits byte of a BIT_STRING. |

`GetASNItem_Addr()` with `GetASNItem_Length()` is how a signed structure gets a
reference to the exact bytes that were signed.

`GetASNItem_UnusedBits()` reads the byte *before* the content, because the
parser has already stepped over it. It is only meaningful for a BIT_STRING that
matched, and only while `.data.ref` still points into the input - see
"BIT STRING" under "Patterns".

Two things to be careful of:

- **`headerOnly` items ignore the binder.** `GetASN_Items()` stores a reference
  and moves on before the registered data type is applied, so a `GetASN_*` call
  on a `headerOnly` item has no effect. Read `.data.ref` instead.
- **`.length` includes the leading byte** for INTEGER and BIT_STRING, so it is
  one more than the number of value bytes stored. See the sections on those two
  types under "Patterns".


# Encoding

Encoding is two passes over the same template. `SizeASN_Items()` works out the
total length of the encoding and fills in each item's offset. `SetASN_Items()`
then writes the encoding and returns its size. The first call is not optional:
`SetASN_Items()` relies on the offsets it leaves behind.

```c
static int Encode<Something>(byte* output, int outLen, <Object Type>* <obj>)
{
    DECL_ASNSETDATA(dataASN, <template>_Length);
    word32 sz = 0;
    int ret = 0;

    CALLOC_ASNSETDATA(dataASN, <template>_Length, ret, <obj>->heap);

    if (ret == 0) {
        /* Set the data for each item. For example:
         *  SetASN_Int8Bit(&dataASN[<TEMPLATE>_IDX_VER], 0);
         *  SetASN_MP(&dataASN[<TEMPLATE>_IDX_N], &<obj>->n);
         *  SetASN_OID(&dataASN[<TEMPLATE>_IDX_OID], RSAk, oidKeyType);
         *
         * Suppress an optional item that is not being written:
         *  dataASN[<TEMPLATE>_IDX_PARAMS].noOut = 1;
         */

        /* Calculate size of encoding. */
        ret = SizeASN_Items(<template>, dataASN, <template>_Length, &sz);
    }
    /* Check the output buffer is big enough. */
    if ((ret == 0) && (output != NULL) && (sz > (word32)outLen)) {
        ret = BUFFER_E;
    }
    if ((ret == 0) && (output != NULL)) {
        /* Write the encoding. */
        SetASN_Items(<template>, dataASN, <template>_Length, output);
    }
    if (ret == 0) {
        /* Return the size of the encoding. */
        ret = (int)sz;
    }

    FREE_ASNSETDATA(dataASN, <obj>->heap);
    return ret;
}
```

Calling with `output` of NULL to size the encoding first, then again with a
buffer, is the usual arrangement. `SetRsaPublicKey()` in `asn.c` is a compact
worked example.

`SetASN_Items()` assumes the buffer is big enough - it does no bounds checking
of its own, so the caller must compare the size from `SizeASN_Items()` against
the buffer before calling it. When a maximum size is needed up front rather
than a computed one, the `MAX_*_SZ` constants are in
`wolfssl/wolfcrypt/types.h`, not `asn.h`; `MAX_SEQ_SZ` is a tag plus the
longest length encoding. `SizeASNHeader(len)` gives the size of one header.

The lengths of SEQUENCEs and other constructed items are computed for you from
the items below them. Do not set them. So are the leading bytes that INTEGER
and BIT_STRING carry - supply the raw value and see the sections on those two
types under "Patterns".

## Reserving space to fill in later

Set a buffer with a length but a NULL pointer and `SetASN_Items()` writes the
header, skips the content, and stores a pointer to the gap it left in
`data.buffer.data`. That is how a structure is wrapped around a body that is
already in the output buffer:

```c
    /* Leave space for body in encoding - address comes back in dataASN. */
    SetASN_ReplaceBuffer(&dataASN[SIGASN_IDX_TBS_SEQ], NULL, (word32)bodySz);
```

Relatedly, the content of a buffer item is copied with `XMEMMOVE`, so the data
being encoded is allowed to overlap the output buffer. `AddSignature()` in
`asn.c` relies on both: it moves the body along to make room for the header,
then encodes around it in place.

## Registering the data to write

| Function | Effect |
|---|---|
| `SetASN_Int8Bit`, `SetASN_Int16Bit`, `SetASN_Int32Bit` | Write an integer value. |
| `SetASN_Int32BitInt` | Write a 32-bit value as INTEGER content even when the item is implicitly tagged. Needs `WOLFSSL_ASN_TEMPLATE_NEED_SET_INT32`. |
| `SetASN_Boolean` | Write a BOOLEAN. |
| `SetASN_Buffer(d, data, len)` | Use the buffer as the item's **content**; the header is generated. |
| `SetASN_ReplaceBuffer(d, data, len)` | The buffer is a **complete encoded item**, header included, and replaces the item entirely. |
| `SetASN_MP` | Write an `mp_int` as an INTEGER. |
| `SetASN_OID(d, oid, oidType)` | Write an OBJECT IDENTIFIER from its id and class. |

`ASNSetData` fields you set directly:

- `noOut = 1` leaves this item out of the encoding. This is how optional items
  are omitted. It applies to the one item, so a constructed item and its
  children need the flag on each - use the helpers below rather than doing it
  by hand and leaving one behind:

  | Macro | Suppresses |
  |---|---|
  | `SetASNItem_NoOut(d, start, end)` | Items `start` to `end` inclusive. |
  | `SetASNItem_NoOutBelow(d, asn, node, len)` | Every item below `node`, but not `node` itself. |
  | `SetASNItem_NoOutNode(d, asn, node, len)` | `node` and everything below it. |
  | `SetASNItem_NoOutNode_ex(d, asn, header, node, len)` | As above, with `header` of 0 when the node has no children to walk. |

  `len` is the template's `_Length`, and `asn` the template itself - the
  subtree forms walk `depth` to find where the children end.
- Supplying `data.buffer.data` for an item marked `headerOnly` overrides
  `headerOnly`: the buffer becomes the content and the template items below it
  are ignored.

Do not set `ASNSetData.offset` or `.length`. Unlike the decode side, where
`offset` is an index into the input, these are computed by `SizeASN_Items()`
for its own use.


# A complete example

BasicConstraints is small enough to show whole and uses most of what has been
described: a wrapping SEQUENCE, an optional BOOLEAN with a DEFAULT, and an
optional INTEGER.

```
  BasicConstraints ::= SEQUENCE {
      cA                 BOOLEAN DEFAULT FALSE,
      pathLenConstraint  INTEGER (0..MAX) OPTIONAL
  }
```

The template, its indices and its length:

```c
/* ASN.1 template for BasicConstraints.
 * X.509: RFC 5280, 4.2.1.9 - BasicConstraints.
 */
static const ASNItem basicConsASN[] = {
/* SEQ  */ { 0, ASN_SEQUENCE, 1, 1, 0 },
/* CA   */     { 1, ASN_BOOLEAN, 0, 0, 1 },
/* PLEN */     { 1, ASN_INTEGER, 0, 0, 1 }
};
enum {
    BASICCONSASN_IDX_SEQ = 0,
    BASICCONSASN_IDX_CA,
    BASICCONSASN_IDX_PLEN
};

/* Number of items in ASN.1 template for BasicConstraints. */
#define basicConsASN_Length (sizeof(basicConsASN) / sizeof(ASNItem))
```

Decoding it. This is `DecodeBasicCaConstraint()` from `asn.c` with its
build-option guards removed, so that the shape is visible:

```c
int DecodeBasicCaConstraint(const byte* input, int sz, byte* isCa,
                            word16* pathLength, byte* pathLengthSet)
{
    DECL_ASNGETDATA(dataASN, basicConsASN_Length);
    int ret = 0;
    word32 idx = 0;
    byte innerIsCA = 0;

    CALLOC_ASNGETDATA(dataASN, basicConsASN_Length, ret, NULL);

    if (ret == 0) {
        /* Get the CA boolean and path length when present. */
        GetASN_Boolean(&dataASN[BASICCONSASN_IDX_CA], &innerIsCA);
        GetASN_Int16Bit(&dataASN[BASICCONSASN_IDX_PLEN], pathLength);

        /* complete is 1 - the template describes the whole encoding. */
        ret = GetASN_Items(basicConsASN, dataASN, basicConsASN_Length, 1,
                           input, &idx, (word32)sz);
    }

    /* An empty SEQUENCE is valid - there is simply nothing to store. */
    if ((ret == 0) && (dataASN[BASICCONSASN_IDX_SEQ].length != 0)) {
        /* Path length must fit in 7 bits. */
        if (*pathLength >= (1 << 7)) {
            ret = ASN_PARSE_E;
        }
        if (ret == 0) {
            *isCa = innerIsCA ? 1 : 0;
            /* A length of 0 means the optional item was not there. */
            *pathLengthSet = (dataASN[BASICCONSASN_IDX_PLEN].length > 0);
        }
    }

    FREE_ASNGETDATA(dataASN, NULL);
    return ret;
}
```

Points worth noting in it. The two optional items have a binder registered
whether or not they turn out to be present - registering costs nothing and an
absent item leaves the variable alone, which is why `innerIsCA` is initialised
to 0 first. Presence is read afterwards from `.length`. And the heap hint is
NULL because there is no object here to take one from.

Encoding the same template. wolfSSL writes BasicConstraints as part of the
larger `certExtsASN`, so there is no standalone encoder in the tree; this is
what one would look like:

```c
static int EncodeBasicCaConstraint(byte* output, int outLen, byte isCa,
                                   word16 pathLength, byte pathLengthSet)
{
    DECL_ASNSETDATA(dataASN, basicConsASN_Length);
    word32 sz = 0;
    int ret = 0;

    CALLOC_ASNSETDATA(dataASN, basicConsASN_Length, ret, NULL);

    if (ret == 0) {
        /* cA is DEFAULT FALSE - only write it when true. */
        if (isCa) {
            SetASN_Boolean(&dataASN[BASICCONSASN_IDX_CA], 1);
        }
        else {
            dataASN[BASICCONSASN_IDX_CA].noOut = 1;
        }
        /* pathLenConstraint is OPTIONAL. */
        if (pathLengthSet) {
            SetASN_Int16Bit(&dataASN[BASICCONSASN_IDX_PLEN], pathLength);
        }
        else {
            dataASN[BASICCONSASN_IDX_PLEN].noOut = 1;
        }

        /* Calculate the size of the encoding. */
        ret = SizeASN_Items(basicConsASN, dataASN, basicConsASN_Length, &sz);
    }
    /* Check the output buffer is big enough. */
    if ((ret == 0) && (output != NULL) && (sz > (word32)outLen)) {
        ret = BUFFER_E;
    }
    if ((ret == 0) && (output != NULL)) {
        /* Write the encoding out. */
        SetASN_Items(basicConsASN, dataASN, basicConsASN_Length, output);
    }
    if (ret == 0) {
        /* Return the size of the encoding. */
        ret = (int)sz;
    }

    FREE_ASNSETDATA(dataASN, NULL);
    return ret;
}
```

The SEQUENCE has nothing set on it: its length comes from the items below.
Calling with `output` of NULL returns the size, so a caller can allocate and
then call again.


# Patterns

## SEQUENCE OF and repetition

A template describes a fixed shape, so repetition is a loop in the caller.
Parse the outer header with one template, then run the element template
repeatedly, clearing the dynamic data and re-registering each time, and
advancing the index yourself past the content of `headerOnly` items.

```c
    while ((ret == 0) && (idx < (word32)sz)) {
        /* Clear dynamic data. */
        XMEMSET(dataASN, 0, sizeof(*dataASN) * certExtASN_Length);
        GetASN_OID(&dataASN[CERTEXTASN_IDX_OID], oidCertExtType);
        GetASN_Int8Bit(&dataASN[CERTEXTASN_IDX_CRIT], &critical);
        /* complete is 0 - this is one element of many. */
        ret = GetASN_Items(certExtASN, dataASN, certExtASN_Length, 0, input,
                           &idx, (word32)sz);
        if (ret == 0) {
            word32 length = dataASN[CERTEXTASN_IDX_VAL].length;

            /* ... handle the element, whose content is at input + idx ... */

            /* Move index on to the next element. */
            idx += length;
        }
    }
```

`DecodeCertExtensions()` in `asn.c` is the full version.

A `SET OF` is the same shape with `ASN_SET` as the outer tag. Note that DER
requires the elements of a SET OF to be sorted by their encodings, and nothing
in the template machinery does that - `SetASN_Items()` writes the items in
template order. Ordering a SET OF correctly is the caller's job.

## Using part of a template

The template and the dynamic data are parallel arrays, so a contiguous run of
items can be used on its own by offsetting both pointers and reducing the
count. This is how one template serves, say, both a bare key and the same key
wrapped in a header.

```c
    /* Start encoding at the item after the header. */
    o = RSAPUBLICKEYASN_IDX_PUBKEY_RSA_SEQ;
    ret = SizeASN_Items(rsaPublicKeyASN + o, dataASN + o,
                        (int)rsaPublicKeyASN_Length - o, &sz);
```

Trailing items can be dropped the same way by passing a smaller count. Both
forms only work on a run that is self-contained: the first item must be at the
outermost depth of the run.

## Parsing nested content

For content that is decoded by a different function - a certificate extension,
an encapsulated key - mark the containing item `headerOnly` and hand
`.data.ref.data` and `.length`, or `input + offset`, to that function. The
offsets recorded during the parse are indices into the original buffer, so no
copying is needed.

## BOOLEAN and NULL

Both are one-line items with no data to register a destination for, and both
are handled from the tag rather than from a data type - which is why
`GetASN_Boolean()` and `SetASN_Boolean()` do not look like the other binders.

```c
/* CRIT */     { 1, ASN_BOOLEAN, 0, 0, 1 },
/* NULL */     { 1, ASN_TAG_NULL, 0, 0, 1 },
```

A BOOLEAN must be exactly one byte of content or the parse fails with
`ASN_PARSE_E`. Any non-zero byte reads as true, which is more lenient than DER,
but encoding is strict: `SetASN_Boolean()` writes `0xFF` for true and `0x00`
for false.

The two calls are not symmetric. `GetASN_Boolean()` takes a **pointer** to the
`byte` to fill in; `SetASN_Boolean()` takes the **value** to write:

```c
    GetASN_Boolean(&dataASN[BASICCONSASN_IDX_CA], &isCA);   /* decode */
    SetASN_Boolean(&dataASN[CERTEXTSASN_IDX_BC_CA], 1);     /* encode */
```

A NULL carries no content and the parser insists on that - a NULL with a
non-zero length is `ASN_EXPECT_0_E`. There is nothing to register; test whether
one was present the usual way, with `.tag`:

```c
    if (dataASN[ALGOIDASN_IDX_NULL].tag == ASN_TAG_NULL) {
```

An AlgorithmIdentifier's parameters is the common place for both a NULL and its
absence to be meaningful, and it is usually written as an optional item or as
one arm of a numbered choice against a SEQUENCE.

### DEFAULT values

ASN.1 `DEFAULT` means the value is omitted from the encoding when it equals the
default, so a `critical BOOLEAN DEFAULT FALSE` is an optional item on decode
and a `noOut` on encode:

```c
    if (cert->basicConstCrit) {
        SetASN_Boolean(&dataASN[CERTEXTSASN_IDX_BC_CRIT], 1);
    }
    else {
        dataASN[CERTEXTSASN_IDX_BC_CRIT].noOut = 1;
    }
```

Nothing in the template says what the default is. On decode, an absent item
leaves `.tag` at 0 and whatever variable was registered untouched, so
initialise it to the default before parsing.

## INTEGER

An INTEGER is written plainly in a template, and the parser does the work of
turning the encoded form into a value:

```c
/*  PUBKEY_RSA_SEQ */         { 2, ASN_SEQUENCE, 1, 1, 0 },
/*  PUBKEY_RSA_N   */             { 3, ASN_INTEGER, 0, 0, 0 },
/*  PUBKEY_RSA_E   */             { 3, ASN_INTEGER, 0, 0, 0 },
```

```c
    GetASN_MP(&dataASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_N], &key->n);
    GetASN_MP(&dataASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_E], &key->e);
```

Pick the binder by size and signedness:

| Binder | For |
|---|---|
| `GetASN_Int8Bit`, `GetASN_Int16Bit`, `GetASN_Int32Bit` | Small values - versions, counts, path lengths. |
| `GetASN_MP` | A big number that must be positive. |
| `GetASN_MP_PosNeg` | A big number that may be negative. |
| `GetASN_MP_Inited` | As `GetASN_MP`, for an `mp_int` already initialised. |

The number binders police the size themselves: after the leading zero has been
stepped over, `GetASN_Int8Bit()` wants exactly one byte, `GetASN_Int16Bit()`
one or two and `GetASN_Int32Bit()` one to four, and anything longer is
`ASN_PARSE_E`. They also refuse a value whose top byte is `0x80` or above -
`ASN_EXPECT_0_E` - since these read the content as unsigned. Use an `mp_int`
for anything that will not fit.

### The leading zero

DER writes a leading `0x00` on an INTEGER whose top bit is set, so that the
value reads as positive. The parser checks that byte and then steps over it, so
the value handed back does not include it - but `.length` was recorded first
and still counts it. Reading `.length` as the size of the value gives a number
one too large.

The checks made on that first byte, all before any binder runs:

- A zero length INTEGER is rejected with `ASN_PARSE_E`.
- A leading `0x00` that was not needed is rejected with `ASN_PARSE_E`.
- A leading `0xff` on a value whose next byte has the top bit set - a
  non-minimal negative - is rejected with `ASN_EXPECT_0_E`.
- A negative value where a positive one was asked for is rejected with
  `ASN_EXPECT_0_E`. `GetASN_MP` and `GetASN_MP_Inited` ask for positive;
  `GetASN_MP_PosNeg` does not.

`WOLFSSL_ASN_INT_LEAD_0_ANY` downgrades all four to a debug message and lets
the encoding through. It is for interoperating with encoders that get this
wrong, not something to define to make a template work.

Encoding is the mirror: supply the value and `SetASN_Int32Bit()`, `SetASN_MP()`
and friends add the `0x00` when the top bit is set. The check is made on the
first byte of what is supplied, so a value that was already padded is written
through unchanged rather than padded twice - but padding a value that did not
need it produces a non-minimal INTEGER that this same parser rejects. Supply
the raw value.

`SetASN_Int32BitInt()` is the odd one out - it encodes a 32-bit value as
INTEGER content even when the template item carries an implicit tag rather than
`ASN_INTEGER`. It needs `WOLFSSL_ASN_TEMPLATE_NEED_SET_INT32`.

## ENUMERATED

An ENUMERATED holds an integer and is bound with the same number binders,
because those are chosen by data type rather than by tag:

```c
/* STATUS */     { 1, ASN_ENUMERATED, 0, 0, 0 },
```

```c
    GetASN_Int8Bit(&dataASN[OCSPRESPONSEASN_IDX_STATUS], &status);
```

What it does **not** get is any of the INTEGER handling above, because that is
selected from the template's tag. Nothing is padded on encode and nothing is
stripped on decode. For the values an enumeration actually holds - a CRL revocation
reason, an OCSP response status - that never shows. It does mean a value of
`0x80` or above will not round trip: the encoder writes one unpadded byte and
the parser then rejects it as negative with `ASN_EXPECT_0_E`.

## BIT STRING

The content of a BIT STRING starts with a count of unused bits in its last
byte. As with an INTEGER's leading zero, the parser validates and steps over
that byte, and as with an INTEGER, `.length` still counts it.

The common case is a BIT STRING wrapping more DER. Mark it `headerOnly` and
carry on describing what is inside; the descent starts after the unused bits
byte, so the nested items line up:

```c
/*  PUBKEY         */     { 1, ASN_BIT_STRING, 0, 1, 0 },
                                                  /* RSAPublicKey */
/*  PUBKEY_RSA_SEQ */         { 2, ASN_SEQUENCE, 1, 1, 0 },
/*  PUBKEY_RSA_N   */             { 3, ASN_INTEGER, 0, 0, 0 },
/*  PUBKEY_RSA_E   */             { 3, ASN_INTEGER, 0, 0, 0 },
```

For a BIT STRING holding bits rather than a structure - a KeyUsage, a CRL
reason - the count itself is read with `GetASNItem_UnusedBits()`. That macro
looks at the byte before the content, because the parser has already stepped
over it, which means it is only valid while `.data.ref` still points into the
input: leave the item unbound, or `headerOnly`. Binding it with
`GetASN_Buffer()` replaces that pointer with the caller's destination buffer
and the macro then reads a byte of unrelated memory. Take the content from
`.data.ref` as well, or read the unused bits first.

Three things are checked, and each fails with `ASN_PARSE_E`:

- A zero length BIT STRING.
- An unused bits count above 7.
- Unused bits that are not actually zero in the last byte.

`GetASN_BitString(input, idx, length)` performs those same checks and is
available for an item the parser did not check itself - a `GetASN_Choice()`
alternative that turned out to be a BIT STRING, for instance.

On encode, a BIT STRING supplied as a **buffer** is written with an unused bits
count of 0; the content is taken exactly as given. To emit a named bit string
with a real count, bind a **number** instead - `SetASN_Int16Bit()` on a
BIT_STRING item encodes it as a named bit string, dropping trailing zero bytes
and computing the unused bits from the trailing zero bits of the last byte.
`SetASN_Int32Bit()` does the same for 32 bits under
`WOLFSSL_ASN_TEMPLATE_NEED_SET_INT32`.

## OCTET STRING

An OCTET STRING is the plain case: no leading byte, and no check on the
content - whatever bytes are there are what comes back. What varies is whether
the template stops at it or carries on into it, which is `headerOnly`.

**As an opaque blob**, leave `headerOnly` at 0. The whole item is stepped over
and the bytes come back by reference, so the outer structure keeps parsing:

```c
/*  PKEY_DATA */        { 1, ASN_OCTET_STRING, 0, 0, 0 },
```

```c
    /* Return the content to the caller to parse. */
    *inOutIdx = GetASNItem_DataIdx(dataASN[PKCS8KEYASN_IDX_PKEY_DATA], input);
    ret = (int)dataASN[PKCS8KEYASN_IDX_PKEY_DATA].data.ref.length;
```

Use `GetASN_Buffer()` instead when a copy into a caller buffer is wanted rather
than a reference.

**Wrapping more DER**, set `headerOnly` to 1 and describe the content with
deeper items. A certificate extension is the usual shape - the value is an
OCTET STRING holding the extension's own encoding:

```c
/* BC_SEQ     */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/* BC_OID     */        { 1, ASN_OBJECT_ID, 0, 0, 0 },
/* BC_CRIT    */        { 1, ASN_BOOLEAN, 0, 0, 0 },
/* BC_STR     */        { 1, ASN_OCTET_STRING, 0, 1, 0 },
/* BC_STR_SEQ */            { 2, ASN_SEQUENCE, 1, 1, 0 },
                                    /* cA */
/* BC_CA      */                { 3, ASN_BOOLEAN, 0, 0, 0 },
                                    /* pathLenConstraint */
/* BC_PATHLEN */                { 3, ASN_INTEGER, 0, 0, 1 },
```

The same template shows the other choice a few items later: a Subject
Alternative Name's value is `{ 1, ASN_OCTET_STRING, 0, 0, 0 }`, opaque, because
that extension is built elsewhere and dropped in whole.

**Wrapping DER that another function parses**, hand the content off as
described under "Parsing nested content". If the item is `headerOnly`, parsing
stops sitting on that content, so advance `idx` past it once the other function
is done - the extension loop under "SEQUENCE OF and repetition" is that shape,
and forgetting to advance leaves it re-reading the same element.

On encode there is nothing special to do either way. Supply the content with
`SetASN_Buffer()` for an opaque one; for a `headerOnly` one the length is
computed from the items below it, exactly like a SEQUENCE. Supplying a buffer
for a `headerOnly` item overrides the children, as described under "Registering
the data to write".

## UTCTime and GeneralizedTime

An ASN.1 `Time` is a CHOICE of two tags, so it is a numbered choice of two
template items. A structure with two times needs two groups, hence the two
available numbers:

```c
                       /* Validity ::= SEQUENCE */
/* VALIDITY_SEQ  */    { 2, ASN_SEQUENCE, 1, 1, 0 },
                       /* notBefore  Time */
                       /* Time ::= CHOICE { UTCTime, GeneralizedTime } */
/* NOTB_UTC      */        { 3, ASN_UTC_TIME, 0, 0, 2 },
/* NOTB_GT       */        { 3, ASN_GENERALIZED_TIME, 0, 0, 2 },
                       /* notAfter   Time */
/* NOTA_UTC      */        { 3, ASN_UTC_TIME, 0, 0, 3 },
/* NOTA_GT       */        { 3, ASN_GENERALIZED_TIME, 0, 0, 3 },
```

Register nothing on them - the content is wanted by reference. After the parse,
find which alternative matched with `.tag`, then use that index for everything
else:

```c
    /* Find the item that holds the notBefore date. */
    i = (dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTB_UTC].tag != 0)
            ? X509CERTASN_IDX_TBS_VALIDITY_NOTB_UTC
            : X509CERTASN_IDX_TBS_VALIDITY_NOTB_GT;
    if (CheckDate(&dataASN[i], ASN_BEFORE) < 0) {
        badDate = ASN_BEFORE_DATE_E;
    }
    /* Store a reference to the whole encoded date item. */
    cert->beforeDate    = GetASNItem_Addr(dataASN[i], cert->source);
    cert->beforeDateLen = (int)GetASNItem_Length(dataASN[i], cert->source);
```

`CheckDate()` takes the dynamic data item directly. It checks the tag is one of
the two time tags, that the length is between `MIN_DATE_SIZE` and
`MAX_DATE_SIZE`, and - unless `NO_ASN_TIME_CHECK` is defined - that the value
parses and is before or after now. It returns `ASN_TIME_E`, `ASN_DATE_SZ_E`,
`ASN_BEFORE_DATE_E` or `ASN_AFTER_DATE_E`. It reads `.data.ref`, so it only
works on an item with no binder registered.

To encode, write one alternative and `noOut` the other:

```c
    if (cert->beforeDate[0] == ASN_UTC_TIME) {
        /* beforeDate holds a whole encoded item - skip its 2 byte header. */
        SetASN_Buffer(&dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTB_UTC],
                cert->beforeDate + 2, ASN_UTC_TIME_SIZE - 1);
        dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTB_GT].noOut = 1;
    }
    else {
        dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTB_UTC].noOut = 1;
        SetASN_Buffer(&dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTB_GT],
                cert->beforeDate + 2, ASN_GEN_TIME_SZ);
    }
```

The asymmetry in those two lengths is not a mistake. A UTCTime's content is 13
bytes (`YYMMDDHHMMSSZ`) and a GeneralizedTime's is 15 (`YYYYMMDDHHMMSSZ`), but
`ASN_UTC_TIME_SIZE` and `ASN_GENERALIZED_TIME_SIZE` are 14 and 16 - they include
room for a terminating NUL. Hence `ASN_UTC_TIME_SIZE - 1` on one side and the
separate `ASN_GEN_TIME_SZ`, which is already a content length, on the other.

Passing a NULL buffer with the right length reserves the space to be filled in
later, which is what certificate generation does when the dates are not yet
known.

## String types

A `DirectoryString` and friends are a CHOICE over several string tags. Write
one template item with a tag of 0 to show the tag comes from elsewhere, and
supply the permitted tags at decode time:

```c
/* X.509: RFC 5280, 4.1.2.4 - DirectoryString */
static const byte rdnChoice[] = {
    ASN_PRINTABLE_STRING, ASN_IA5_STRING, ASN_UTF8STRING, ASN_T61STRING,
    ASN_UNIVERSALSTRING, ASN_BMPSTRING, ASN_BIT_STRING, 0
};

static const ASNItem rdnASN[] = {
/* SET       */ { 1, ASN_SET, 1, 1, 0 },
/* ATTR_SEQ  */     { 2, ASN_SEQUENCE, 1, 1, 0 },
/* ATTR_TYPE */         { 3, ASN_OBJECT_ID, 0, 0, 0 },
                        /* AttributeValue: Choice of tags - rdnChoice. */
/* ATTR_VAL  */         { 3, 0, 0, 0, 0 },
};
```

```c
    GetASN_Choice(&dataASN[RDNASN_IDX_ATTR_VAL], rdnChoice);
    /* Ignore the type OID - too many to store in a table. */
    GetASN_OID(&dataASN[RDNASN_IDX_ATTR_TYPE], oidIgnoreType);
    ret = GetASN_Items(rdnASN, dataASN, rdnASN_Length, 1, input, &srcIdx,
                       maxIdx);
```

Afterwards the tag says which string type arrived, and the value comes out by
reference:

```c
    byte        tag = dataASN[RDNASN_IDX_ATTR_VAL].tag;
    const byte* str;
    word32      strLen;

    GetASN_GetRef(&dataASN[RDNASN_IDX_ATTR_VAL], &str, &strLen);
```

Two things follow from the tag being unknown until run time:

- **UTF8STRING content is still validated**, because that check looks at the
  tag found as well as the tag in the template. `WOLFSSL_NO_ASN_STRICT` turns it
  off.
- **A BIT_STRING alternative arrives unstripped.** The special handling for
  that type keys off the template's tag, which is 0 here, so the unused bits
  byte is the first byte of `str` - see "BIT STRING" above.

Encoding a choice needs the opposite: a tag that is only known at run time,
where the template is `const`. Copy the template to a local array and patch the
one item:

```c
    ASNItem namesASN[rdnASN_Length];

    /* Copy the RDN encoding template. ASN.1 tag for the name string is set
     * based on type. */
    XMEMCPY(namesASN, rdnASN, sizeof(namesASN));
    SetASN_Buffer(&dataASN[RDNASN_IDX_ATTR_VAL], (const byte*)nameStr, nameSz);
    namesASN[RDNASN_IDX_ATTR_VAL].tag = nameTag;

    ret = SizeASN_Items(namesASN, dataASN, rdnASN_Length, &sz);
```

`EncodeName()` in `asn.c` does exactly this. The pattern is not specific to
strings - it is how any item whose tag or optionality varies gets encoded.

## OIDs

OIDs are handled as a 32-bit id rather than as bytes. `GetASN_OID()` validates
an OBJECT IDENTIFIER against a class and produces that id in `.data.oid.sum`,
which is what the rest of the code switches on. The classes are the `oid*Type`
enum in `asn.h` - `oidHashType`, `oidSigType`, `oidKeyType`, `oidCertExtType`
and the rest - and passing the right one is what makes an unexpected OID fail
with `ASN_UNKNOWN_OID_E` instead of being accepted.

`SetASN_OID()` goes the other way, looking the id up with
`OidFromId(id, type, &sz)`. That lookup **returns NULL when the OID is not
compiled into this build**, and `SetASN_OID()` has no way to report it, so
check for it:

```c
    SetASN_OID(&dataASN[SIGASN_IDX_SIGALGO_OID], sigAlgoType, oidSigType);
    if (dataASN[SIGASN_IDX_SIGALGO_OID].data.buffer.data == NULL) {
        /* The OID was not found or compiled in! */
        ret = ASN_UNKNOWN_OID_E;
    }
```

To add a new OID, compute its sum with `scripts/asn1_oid_sum.pl` and add the
byte array and the id to the tables in `asn.c` that `OidFromId()` and `GetOID()`
walk.

## Templates in another file

Templates do not have to live in `asn.c`, but a file holding them is
`#include`d into `asn.c` rather than compiled on its own -
`wolfcrypt/src/asn_tsp.c` is the worked example. Such a file guards itself so
that building it standalone is a warning and an empty translation unit:

```c
#if !defined(WOLFSSL_ASN_TSP_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning asn_tsp.c does not need to be compiled separately from asn.c
    #endif
#else
...
#endif
```

Inside, everything is also inside `#ifdef WOLFSSL_ASN_TEMPLATE`, because
`ASNItem` and the whole API only exist in that build.


# Pitfalls

Collected here because most of them fail quietly rather than loudly.

| Mistake | What happens |
|---|---|
| An `#if` around a table entry but not around its enumerator | Every index after it is off by one. The template decodes into the wrong fields; nothing warns. |
| `count` argument not matching the template it is passed with | Items are read past the end of the table, or the tail of the template is ignored. |
| Reusing a `dataASN` array for a second parse without clearing it | Stale `tag` values make absent optional items look present. Clear it each time round a loop. |
| Registering a `GetASN_*` binder on a `headerOnly` item | The binder is ignored; the data arrives in `.data.ref`. A `GetASN_Choice()` list on such an item is not checked either. |
| Expecting an `optional` `GetASN_Choice()` item to skip an unlisted tag | It is `ASN_PARSE_E`. A choice item reads as absent only when the enclosing item is used up. |
| Treating `.length` as the value length for an INTEGER or BIT_STRING | It is one larger - the leading zero pad or unused bits byte is counted. |
| Expecting that same leading byte to be stripped from a `GetASN_Choice()` item | It is not. The parser decides from the template's tag, which is 0 for a choice, so the caller gets the raw first byte. |
| `ASN_CONSTRUCTED` ORed into a template tag | Nothing matches. `constructed` is a separate field. The tag lists for `GetASN_Choice()` are the exception. |
| Padding an INTEGER with a leading zero by hand before encoding | Not doubled - the encoder looks at the first byte supplied - but a `0x00` on a value that did not need one is a non-minimal INTEGER, which the parser rejects. |
| `complete` of 1 when parsing one element of a larger structure | `ASN_PARSE_E` as soon as a sibling follows. |
| Declaring `ASNGetData dataASN[N]` instead of `DECL_ASNGETDATA` | Builds, then blows the stack in a `WOLFSSL_SMALL_STACK` configuration. |
| `noOut` on a constructed item only | Its children are still encoded. Use `SetASNItem_NoOutNode()`. |
| `SetASN_Items()` without `SizeASN_Items()` first | Offsets are unset; output is garbage. |
| Not checking `data.buffer.data` after `SetASN_OID()` | An OID missing from the build encodes as nothing instead of failing. |
| A binder given the wrong pointer width | Silent memory corruption - the binders are macros. Build once with `WOLFSSL_ASN_TEMPLATE_TYPE_CHECK`. |
| An early return between `CALLOC_` and `FREE_` | Leaks under `WOLFSSL_SMALL_STACK`. Keep the `ret == 0` chain and one exit. |


# Limits, errors and debugging

## Limits

- Maximum template depth is `GET_ASN_MAX_DEPTH`, currently 8. Exceeding it is a
  runtime `ASN_PARSE_E`, not a compile error.
- Numbered choices are limited to the values 2 and 3
  (`GET_ASN_MAX_CHOICES`, currently 2).
- The parser reads definite-length encodings. An indefinite length (0x80) is
  read as a length of 0, so indefinite-length BER cannot be described with a
  template. Convert it first with `wc_BerToDer()` and parse the result, as
  `pkcs7.c` and `pkcs12.c` do.
- UTF8STRING content is validated unless `WOLFSSL_NO_ASN_STRICT` is defined.

## Return codes from GetASN_Items()

| Code | Cause |
|---|---|
| `0` | Success. |
| `ASN_PARSE_E` | Tag did not match, constructed did not match, data left over when `complete` was set, depth too great, or a required choice was absent. |
| `BUFFER_E` | Ran off the end of the input, or a `GetASN_Buffer()` destination was too small. |
| `ASN_OBJECT_ID_E` | An OBJECT IDENTIFIER was expected and not found. |
| `ASN_BITSTR_E` | A BIT STRING was expected and not found. |
| `ASN_EXPECT_0_E` | INTEGER with the MSB set, or a NULL with a non-zero length. |
| `ASN_UNKNOWN_OID_E` | The OID did not verify against the class given to `GetASN_OID()`. |
| `MP_INIT_E`, `ASN_GETINT_E` | Failed to initialise or fill an `mp_int`. |
| `BAD_STATE_E` | Unsupported data type registered. |
| `MEMORY_E` | Allocation failed in `ALLOC_`/`CALLOC_ASNGETDATA`. |

`SizeASN_Items()` returns 0 or `BAD_STATE_E`; `SetASN_Items()` returns the size
of the encoding.

## Tracing a template

Define `WOLFSSL_DEBUG_ASN_TEMPLATE` to get a per-item trace of what the parser
matched, and a message naming the item and the tag found when it fails. There
is no configure option for it: it is behind `DEBUG_WOLFSSL` and an `#if 0` in
`asn.c` that has to be changed by hand.

```c
#ifdef DEBUG_WOLFSSL
    /* Enable this when debugging the parsing or creation of ASN.1 data. */
    #if 1
        #define WOLFSSL_DEBUG_ASN_TEMPLATE
    #endif
#endif
```

Build with `--enable-debug`, call `wolfSSL_Debugging_ON()`, and each item is
printed as index, offset, length, a `+` when constructed, indented by depth,
with the tag name. With it defined the three entry points also print the name
of the template being used.

To see what the encoding actually contains, `examples/asn1` will dump a DER or
PEM file item by item.

## Type checking the binders

By default the `GetASN_*` and `SetASN_*` binders are macros, so the compiler
never sees the type of what is being registered. Passing a `word32*` where
`GetASN_Int8Bit()` expects a `byte*` builds without a warning and writes past
the variable at run time.

Define `WOLFSSL_ASN_TEMPLATE_TYPE_CHECK` and they become real functions with
prototypes, and the compiler catches the mismatch. There is no configure option
- add it to `CFLAGS` - and it is worth building with once whenever binders are
added or changed.

## Building and testing a change

Run from the root of the checkout. A git checkout needs `./autogen.sh` once
before the first `./configure`.

Build with a broad feature set, so that templates behind less common options
are compiled too:

```sh
./autogen.sh
./configure --enable-all
make -j
```

Run the ASN.1 tests. API level tests for this code are in
`tests/api/test_asn.c`:

```sh
./tests/unit.test --group asn
./tests/unit.test -~<substring of a test name>
./tests/unit.test --list
```

Run the whole suite before proposing the change:

```sh
make -j check
```

Build once with the binders type checked. This catches a destination variable
of the wrong width, which is otherwise silent:

```sh
./configure --enable-all CFLAGS="-DWOLFSSL_ASN_TEMPLATE_TYPE_CHECK"
make -j
```

Build the other side of the small stack switch, which changes how the dynamic
data is declared:

```sh
./configure --enable-all --enable-smallstack
make -j check
```

Build the other ASN.1 implementation if the structure is handled there too:

```sh
./configure --enable-asn=original
make -j check
```

Check source hygiene - trailing whitespace, non-ASCII, tabs and the rest of
what CI enforces:

```sh
.github/scripts/check-source-text.sh wolfcrypt/src/asn.c wolfssl/wolfcrypt/asn.h
```

C sources and headers are held to 80 columns.


# Checklist

Walk this before proposing a change. Each line is a yes/no question with a
definite answer; "Pitfalls" says what goes wrong when the answer is no.

The template:

- Does every item in the table have an enumerator, in the same order?
- Is every `#if` in the table repeated around the matching enumerator?
- Does the enum end with `WOLF_ENUM_DUMMY_LAST_ELEMENT`?
- Is `depth` one greater for each item inside a constructed item?
- Is `constructed` set on every SEQUENCE, SET and EXPLICIT wrapper, and is
  `ASN_CONSTRUCTED` absent from every tag?
- Does every item whose content is described by further items have
  `headerOnly` of 1?
- Are the numbered choice groups adjacent, at one depth, and using only 2
  and 3?

Decoding:

- Is the array declared with `DECL_ASNGETDATA` and not as a plain array?
- Is the count passed to `GetASN_Items()` the template's `_Length`, or a
  matching reduced count when part of the template is used?
- Is `complete` 1 only when the template covers the whole encoding?
- Is `FREE_ASNGETDATA` reached on every path out, with the same heap hint as
  `CALLOC_ASNGETDATA`?
- Is presence of an optional item tested with `.tag` or `.length`, rather than
  assumed?
- Is any variable behind an optional item initialised before the parse?
- Is the array cleared again before each pass when parsing in a loop?
- Does anything read `.length` on an INTEGER or BIT_STRING as if it were the
  value length?
- Is a binder registered on a `headerOnly` item, where it will be ignored?

Encoding:

- Is `SizeASN_Items()` called before `SetASN_Items()`?
- Is the size checked against the output buffer before writing?
- Is `noOut` set on every item that is not being written, children included?
- Is the return of `SetASN_OID()` checked by testing `data.buffer.data` for
  NULL?
- Is anything set on a constructed item's length, which is computed?

Building:

- Does it build with `WOLFSSL_ASN_TEMPLATE_TYPE_CHECK`?
- Does it build and pass tests both with and without `--enable-smallstack`?
- Does the other implementation need the same change, and does
  `--enable-asn=original` still build?
- Is there a test in `tests/api/test_asn.c`, registered in `test_asn.h`?
- Does `check-source-text.sh` pass, and is everything within 80 columns?
