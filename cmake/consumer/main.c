#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

int main(void)
{
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        return 1;
    }
    wolfSSL_Cleanup();
    return 0;
}
