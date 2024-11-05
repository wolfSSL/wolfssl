# Writing an ASN Template

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
/*  <ITEM_0> */ { <depth>, <ASN Type>, <constructed>, <header>, <optional> },
...
};
/* Named indices for <template>. */
enum {
    <TEMPLATE>_<ITEM_0> = 0,
    <TEMPLATE>_<ITEM_1>,
    ...
};
/* Number of items in <template>. */
#define <template>_Length (sizeof(<template>) / sizeof(ASNItem))
```

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
        { 1, ASN_COTET_STRING, 0, 1, 0 },
```

### Context Specific

Content specific ASN.1 items need the value associated with them.

This is a constructed ASN.1 Content Specific item of 1 that is optional.

ASN.1 description would be something like:
```
  maskGenAlgorithm  [1] MaskGeneration Default mgf1SHA1
```


```c
        { 1, ASN_CONTENT_SPECIFIC | 1, 1, 1, 1 },
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

### Choice

Next ASN.1 item, at depth 2, is one of multiple types:

```c
            { 2, ASN_TAG_NULL, 0, 0, 2 },
            { 2, ASN_OBJECT_ID, 0, 0, 2 },
            { 2, ASN_SEQUENCE, 1, 0, 2 },
```

Note, use the optional value to uniquely identify the choices.



# Decoding function outline

An outline of a decoding function:

```c
#include <wolfssl/wolfcrypt/asn.h>

...

static int Decode<Something>(const byte* input, int sz, <Object Type* <obj>)
{
    DECL_ASNGETDATA(dataASN, <template>_Length);
    int ret = 0;
    /* Declare variables to parse data into. For example:
     *   word32 idx = 0;
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

