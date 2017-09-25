#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/ssl.h>

#include <stdint.h>
#include <stdio.h>

#include <fuzz/fuzzer.h>

int main(int argc, char **argv)
{
    int      i;
    size_t   n_read;
    size_t   sz;
    XFILE    file;
    uint8_t *data;

    /* identify yourself */
    /* @Aesthetic: long name. Get a shorter one. */
    printf("%s:\n", argv[0]);

    /* loop over the remaining argument vector */
    for (i = 1; i < argc; ++i) {
        data = NULL;
        file = XBADFILE;

        /* identify your input */
        printf("\t%s\n", argv[i]);

        /* open the argument as a file */
        /* @Temporary: assume every argument is a file */
        if ((file = XFOPEN(argv[i], "rb")) == XBADFILE) {
            fprintf(stderr, "ERROR: failed to open file.\n");
            goto error;
        }

        /* get the length of the file */
        XFSEEK(file, 0, SEEK_END);
        sz = XFTELL(file);
        XREWIND(file);

        /* allocate a buffer to hold the file */
        if ((data = (uint8_t*)XMALLOC(sz, NULL, DYNAMIC_TYPE_CERT)) == NULL) {
            fprintf(stderr, "ERROR: out of memmory.\n");
            goto error;
        }

        /* load said buffer */
        if ((n_read = XFREAD(data, 1, sz, file)) != sz) {
            fprintf(stderr, "ERROR: failed to read the whole file.\n");
            goto error;
        }

        XFCLOSE(file);

        /* pass it on. If there's a problem, this won't return */
        LLVMFuzzerTestOneInput(data, sz);

        XFREE(data, NULL, DYNAMIC_TYPE_CERT);
    }

    /* If we made it this far, then nothing failed on us. */
    return 0;
error:
    if (data != NULL)     XFREE(data, NULL, DYNAMIC_TYPE_CERT);
    if (file != XBADFILE) XFCLOSE(file);

    return -1;
}
