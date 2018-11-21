# wolfSSL unit tests

The test contains of wolfSSL unit-test app on Unity.

When you want to run the app  
1. Copy *test.c* file at /path/to/esp-idf/components/wolfssl/wolfcrypt/test/ folder to the  wolfssl/test folder  
2. Copy *user_settings.h* to /esp-idf/components/wolfssl/  
3. Add *CFLAGS += -DWOLFSSL_USER_SETTINGS* into components.mk at wolfssl/  
OR, copy *component_wolfssl.mk.use* into wolfssl/ folder  
4. Go to /esp-idf/tools/unit-test-app/ folder  
5. "make menuconfig" to configure unit test app.  
6. "make TEST_COMPONENTS=wolfssl" to build wolfssl unit test app.  

NOTE:  
 You should remove *user_settings.h* file at wolfssl/ folder after finishing run  
 the unit test app.

See [https://docs.espressif.com/projects/esp-idf/en/latest/api-guides/unit-tests.html] for more information about unit test app.
