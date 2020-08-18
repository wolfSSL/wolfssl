/* http://h-wrt.com/en/mini-how-to/autotoolsSimpleModule */

/*  src/module_hello.c */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>

static int __init wolfssl_init(void)
{
    int ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        pr_err("wolfSSL_Init() failed: %s", wc_GetErrorString(ret));
        return -ENOTRECOVERABLE;
    }

    pr_info("wolfSSL " LIBWOLFSSL_VERSION_STRING " loaded. See https://www.wolfssl.com/ for information.\n");
    pr_info("Copyright (C) 2006-2020 wolfSSL Inc. All Rights Reserved.\n");

    return 0;
}

module_init(wolfssl_init);

static void __exit wolfssl_exit(void)
{
    int ret = wolfSSL_Cleanup();
    if (ret != WOLFSSL_SUCCESS)
        pr_err("wolfSSL_Cleanup() failed: %s", wc_GetErrorString(ret));

    return;
}

module_exit(wolfssl_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("https://www.wolfssl.com/");
MODULE_DESCRIPTION("libwolfssl cryptographic and protocol facilities");
MODULE_VERSION(LIBWOLFSSL_VERSION_STRING);
