#include <wolfssl/wolfcrypt/wc_port.h>

    int wc_InitMutex(wolfSSL_Mutex* m)
    {
        (void)m;
        return 0;
    }

    int wc_FreeMutex(wolfSSL_Mutex *m)
    {
        (void)m;
        return 0;
    }


    int wc_LockMutex(wolfSSL_Mutex *m)
    {
        (void)m;
        return 0;
    }


    int wc_UnLockMutex(wolfSSL_Mutex *m)
    {
        (void)m;
        return 0;
    }