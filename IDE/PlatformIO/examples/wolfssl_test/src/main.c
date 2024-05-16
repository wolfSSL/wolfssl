#include <wolfssl/wolfcrypt/settings.h>
#ifdef WOLFSSL_ESPIDF
    #include <esp_log.h>
    #include <rtc_wdt.h>
    #include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#endif
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfcrypt/test/test.h>
#define TAG "demo"

void app_main() {
    int ret = 0;
#ifdef WOLFSSL_ESPIDF
    ESP_LOGI(TAG, "Found WOLFSSL_ESPIDF!");
#endif
    printf("Hello World wolfSSL Version\n %s", LIBWOLFSSL_VERSION_STRING);

#if defined(HAVE_VERSION_EXTENDED_INFO) && defined(WOLFSSL_ESPIDF)
    esp_ShowExtendedSystemInfo();
#endif
    ret = wolf_test_task();
    printf("wolf_test_task result %d", ret);
}
