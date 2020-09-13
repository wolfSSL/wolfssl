# wolfSSL unit-test app

The test contains of wolfSSL unit-test app on Unity.

When you want to run the app  
1. Copy *test.c* file at /path/to/esp-idf/components/wolfssl/wolfcrypt/test/ folder to the  wolfssl/test folder  
2. Go to /esp-idf/tools/unit-test-app/ folder  
3. "idf.py menuconfig" to configure unit test app.  
4. "idf.py -T wolfssl build" to build wolfssl unit test app.  

See [https://docs.espressif.com/projects/esp-idf/en/latest/api-guides/unit-tests.html] for more information about unit test app.
