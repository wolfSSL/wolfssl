/*
* wolfssl sha tests
*/

#include <stdio.h>
#include <string.h>

#include <esp_system.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "unity.h"
#include "sdkconfig.h"
#include "esp_log.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/types.h>

static const char* TAG = "wolfssl unit test";
static xSemaphoreHandle exit_semaph;
static volatile bool exit_loop=false;

#define SHA_STACK_SIZE (20*1024)
#define TIMES_SHA 500
#define TIMES_AES 100

#ifndef NO_SHA
int sha_test();
#endif
#ifndef NO_SHA256
int sha256_test();
#endif
#ifdef WOLFSSL_SHA384
int sha384_test(void);
#endif
#ifdef WOLFSSL_SHA512
int sha512_test(void);
#endif

#ifndef NO_AES
int aes_test(void);
static void tskAes_Test(void *pvParam)
{
    ESP_LOGI(TAG, "enter tskAes_Test");
    int ret = 0;
    while(exit_loop==false) {
        ret = aes_test();
        if(ret != 0) {
            printf("result was not good(aes_test)(%d)\n",ret);
            TEST_FAIL_MESSAGE("tskAes_Test\n");
        }
    }

    ESP_LOGI(TAG, "leave tskAes_Test");
    xSemaphoreGive(exit_semaph);
    vTaskDelete(NULL);
}

int aesgcm_test(void);

static void tskAesGcm_Test(void *pvParam)
{
    ESP_LOGI(TAG, "enter tskAesGcm_Test");
    int ret = 0;
    while(exit_loop==false) {
        ret = aesgcm_test();
        if(ret != 0) {
            printf(" results was not good(%d). aesGcm_test\n",ret);
            TEST_FAIL_MESSAGE("aesGcm_test\n");
        }
    }
    ESP_LOGI(TAG, "leave tskAesGcm_Test");
    xSemaphoreGive(exit_semaph);
    vTaskDelete(NULL);
}

#ifdef WOLFSSL_AES_192
int aes192_test(void);
static void tskAes192_Test(void *pvParam)
{
    ESP_LOGI(TAG, "enter tskAes192_Test");
    int ret = 0;
    while(exit_loop==false) {
        ret = aes192_test();
        if(ret != 0) {
            printf(" results was not good(%d). aes192_test\n",ret);
            TEST_FAIL_MESSAGE("aes192_test\n");
        }
    }
    ESP_LOGI(TAG, "leave tskAes192_Test");
    xSemaphoreGive(exit_semaph);
    vTaskDelete(NULL);
}
#endif
#ifdef WOLFSSL_AES_256
int aes256_test(void);
static void tskAes256_Test(void *pvParam)
{
    ESP_LOGI(TAG, "enter tskAes256_Test");
    int ret = 0;
    while(exit_loop==false) {
        ret = aes256_test();
        if(ret != 0) {
            printf(" results was not good(%d). aes256_test\n", ret);
            TEST_FAIL_MESSAGE("aes256_test\n");
        }
    }
    ESP_LOGI(TAG, "leave tskAes256_Test");
    xSemaphoreGive(exit_semaph);
    vTaskDelete(NULL);
}
#endif

TEST_CASE("wolfssl aes test"  , "[wolfssl]")
{
    ESP_LOGI(TAG, "aes test");
    TEST_ASSERT_EQUAL(0, aes_test());
#ifdef WOLFSSL_AES_192
    ESP_LOGI(TAG, "aes_192 test");
    TEST_ASSERT_EQUAL(0, aes192_test());
#endif
#ifdef WOLFSSL_AES_256
    ESP_LOGI(TAG, "aes_256 test");
    TEST_ASSERT_EQUAL(0, aes256_test());
#endif
    ESP_LOGI(TAG, "aes-gcm test");
    TEST_ASSERT_EQUAL(0, aesgcm_test());
}

#endif

TEST_CASE("wolfssl sha crypt-test", "[wolfssl]")
{
#ifndef NO_SHA
    ESP_LOGI(TAG, "sha_test()");
    TEST_ASSERT_EQUAL(0, sha_test());
#endif
#ifndef NO_SHA256
    ESP_LOGI(TAG, "sha256_test()");
    TEST_ASSERT_EQUAL(0, sha256_test());
#endif
#ifdef WOLSSL_SHA384
    ESP_LOGI(TAG, "sha384_test()");
    TEST_ASSERT_EQUAL(0, sha384_test());
#endif
#ifdef WOLFSSL_SHA512
    ESP_LOGI(TAG, "sha512_test()");
    TEST_ASSERT_EQUAL(0, sha512_test());
#endif
}


#ifndef NO_SHA
static void tskSha_Test(void *pvParam)
{
    ESP_LOGI(TAG, "enter tskSha_Test");

    int ret = 0;

    while(exit_loop==false) {
        ret = sha_test();
        if(ret != 0) {
            printf(" results was not good(%d). sha_test\n", ret);
            TEST_FAIL_MESSAGE("tskSha_Test\n");
        }
    }

    ESP_LOGI(TAG, "leave tskSha_Test");
    xSemaphoreGive(exit_semaph);
    vTaskDelete(NULL);
}
#endif

#ifndef NO_SHA256
static void tskSha256_Test(void *pvParam)
{
    ESP_LOGI(TAG, "enter tskSha256_Test");
    int ret;

    while(exit_loop==false) {
        ret = sha256_test();
        if(ret != 0) {
            printf("results was not good(%d). sha256_test\n", ret);
            TEST_FAIL_MESSAGE("sha256_test() failed");
        }
    }

    ESP_LOGI(TAG, "leave tskSha256_Test");
    xSemaphoreGive(exit_semaph);
    vTaskDelete(NULL);
}
#endif

#ifdef WOLFSSL_SHA384
static void tskSha384_Test(void *pvParam)
{
    ESP_LOGI(TAG, "enter tskSha384_Test");
    int ret = 0;

    while(exit_loop==false) {
        ret = sha384_test();
        if(ret != 0) {
            printf("results was not good(%d). sha384_test\n", ret);
            TEST_FAIL_MESSAGE("sha384_test() failed\n");
        }
    }

    ESP_LOGI(TAG, "leave tskSha384_Test");
    xSemaphoreGive(exit_semaph);
    vTaskDelete(NULL);
}
#endif

#ifdef WOLFSSL_SHA512
static void tskSha512_Test(void *pvParam)
{
    ESP_LOGI(TAG, "enter tskSha512_Test");

    int ret = 0;

    while(exit_loop==false) {
        ret = sha512_test();
        if(ret != 0) {
            printf(" results was not good(%d). sha512_test\n", ret);
            TEST_FAIL_MESSAGE("tskSha512_Test() failed\n");
        }
    }
    ESP_LOGI(TAG, "leave tskSha512_test()");
    xSemaphoreGive(exit_semaph);
    vTaskDelete(NULL);


}
#endif

TEST_CASE("wolfssl sha multi-thread test ", "[wolfssl]")
{
    int num = 0;
#ifndef NO_SHA
    num++;
#endif
#ifndef NO_SHA256
    num++;
#endif
#ifdef WOLFSSL_SHA384
    num++;
#endif
#ifdef WOLFSSL_SHA512
    num++;
#endif

    exit_loop = false;

    exit_semaph = xSemaphoreCreateCounting(num, 0);

#ifndef NO_SHA
    xTaskCreate(tskSha_Test, "sha_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif
#ifndef NO_SHA256
    xTaskCreate(tskSha256_Test, "sha256_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif
#ifdef WOLFSSL_SHA384
    xTaskCreate(tskSha384_Test, "sha384_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif
#ifdef WOLFSSL_SHA512
    xTaskCreate(tskSha512_Test, "sha512_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif

 ESP_LOGI(TAG, "Waiting for 10s ...");
 vTaskDelay(10000/portTICK_PERIOD_MS);
 exit_loop = true;

 for(int i=0;i<num;i++){
     if(!xSemaphoreTake(exit_semaph, 2000/portTICK_PERIOD_MS)) {
         TEST_FAIL_MESSAGE("exit semaphore not released by test task");
     }
 }
 vSemaphoreDelete(exit_semaph);
}

TEST_CASE("wolfssl aes multi-thread test ", "[wolfssl]")
{
    int num = 0;
#ifndef NO_AES
    num++;
    num++;
#ifdef WOLFSSL_AES_192
    num++;
#endif
#ifdef WOLFSSL_AES_256
    num++;
#endif
#endif

    exit_loop = false;
    exit_semaph = xSemaphoreCreateCounting(num, 0);

#ifndef NO_AES
    xTaskCreate(tskAes_Test, "Aes_test", SHA_STACK_SIZE, NULL, 3, NULL);
    xTaskCreate(tskAesGcm_Test, "AesGcm_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif
#ifdef WOLFSSL_AES_192
    xTaskCreate(tskAes192_Test, "Aes192_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif
#ifdef WOLFSSL_AES_256
    xTaskCreate(tskAes256_Test, "Aes256_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif

 ESP_LOGI(TAG, "Waiting for 10s ...");
 vTaskDelay(10000/portTICK_PERIOD_MS);
 exit_loop = true;

 for(int i=0;i<num;i++){
    if(!xSemaphoreTake(exit_semaph, 2000/portTICK_PERIOD_MS)) {
        TEST_FAIL_MESSAGE("exit semaphore not released by test task");
    }
 }
 vSemaphoreDelete(exit_semaph);
}

TEST_CASE("wolfssl aes sha sha256 multi-thread test ", "[wolfssl]")
{
    int num = 0;

#ifndef NO_AES
    num++;
    num++;
#ifdef WOLFSSL_AES_192
    num++;
#endif
#ifdef WOLFSSL_AES_256
    num++;
#endif
#endif
#ifndef NO_SHA
    num++;
#endif
#ifndef NO_SHA256
    num++;
#endif

    exit_loop = false;

#ifndef CONFIG_FREERTOS_UNICORE
    num *= 2;
    printf("num=%d\n", num);

    exit_semaph = xSemaphoreCreateCounting(num, 0);

#ifndef NO_AES
    if(xTaskCreatePinnedToCore(tskAes_Test, "Aes_test", SHA_STACK_SIZE, NULL, 3, NULL, 0)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -1 \n");
    if(xTaskCreatePinnedToCore(tskAes_Test, "Aes_test", SHA_STACK_SIZE, NULL, 3, NULL, 1)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -2 \n");
    if(xTaskCreatePinnedToCore(tskAesGcm_Test, "AesGcm_test", SHA_STACK_SIZE, NULL, 3, NULL, 0)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -3 \n");
    if(xTaskCreatePinnedToCore(tskAesGcm_Test, "AesGcm_test", SHA_STACK_SIZE, NULL, 3, NULL, 1)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -4 \n");
#endif
#ifdef WOLFSSL_AES_192
    if(xTaskCreatePinnedToCore(tskAes192_Test, "Aes192_test", SHA_STACK_SIZE, NULL, 3, NULL, 0)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -5 \n");
    if(xTaskCreatePinnedToCore(tskAes192_Test, "Aes192_test", SHA_STACK_SIZE, NULL, 3, NULL, 1)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -6 \n");
#endif
#ifdef WOLFSSL_AES_256
    if(xTaskCreatePinnedToCore(tskAes256_Test, "Aes256_test", SHA_STACK_SIZE, NULL, 3, NULL, 0)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -7 \n");
    if(xTaskCreatePinnedToCore(tskAes256_Test, "Aes256_test", SHA_STACK_SIZE, NULL, 3, NULL, 1)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -8 \n");
#endif
#ifndef NO_SHA
    if(xTaskCreatePinnedToCore(tskSha_Test, "Sha_test", SHA_STACK_SIZE, NULL, 3, NULL, 0)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -9 \n");
    if(xTaskCreatePinnedToCore(tskSha_Test, "Sha_test", SHA_STACK_SIZE, NULL, 3, NULL, 1)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -10 \n");
#endif
#ifndef NO_SHA256
    if(xTaskCreatePinnedToCore(tskSha256_Test, "sha256_test", SHA_STACK_SIZE, NULL, 3, NULL, 0)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -11 \n");
    if(xTaskCreatePinnedToCore(tskSha256_Test, "sha256_test", SHA_STACK_SIZE, NULL, 3, NULL, 1)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -12 \n");
#endif

#else

    exit_semaph = xSemaphoreCreateCounting(num, 0);

#ifndef NO_AES
    xTaskCreate(tskAes_Test, "Aes_test", SHA_STACK_SIZE, NULL, 3, NULL);
    xTaskCreate(tskAesGcm_Test, "AesGcm_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif
#ifdef WOLFSSL_AES_192
    xTaskCreate(tskAes192_Test, "Aes192_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif
#ifdef WOLFSSL_AES_256
    xTaskCreate(tskAes256_Test, "Aes256_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif
#ifndef NO_SHA
    xTaskCreate(tskSha_Test, "Sha_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif
#ifndef NO_SHA256
    xTaskCreate(tskSha256_Test, "sha256_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif

#endif /* CONFIG_FREERTOS_UNICORE */

    ESP_LOGI(TAG, "Waiting for 15s ...");
    vTaskDelay(15000/portTICK_PERIOD_MS);
    exit_loop = true;

    for(int i=0;i<num;i++){
       if(!xSemaphoreTake(exit_semaph, 2000/portTICK_PERIOD_MS)) {
           TEST_FAIL_MESSAGE("exit semaphore not released by test task");
       }
    }
    vSemaphoreDelete(exit_semaph);
}

TEST_CASE("wolfssl aes sha384 sha512 multi-thread test ", "[wolfssl]")
{
    int num = 0;

#ifndef NO_AES
    num++;
    num++;
#ifdef WOLFSSL_AES_192
    num++;
#endif
#ifdef WOLFSSL_AES_256
    num++;
#endif
#endif
#ifdef WOLFSSL_SHA384
    num++;
#endif
#ifdef WOLFSSL_SHA512
    num++;
#endif


    exit_loop = false;

#ifndef CONFIG_FREERTOS_UNICORE
    num *= 2;
    exit_semaph = xSemaphoreCreateCounting(num, 0);

#ifndef NO_AES
    if(xTaskCreatePinnedToCore(tskAes_Test, "Aes_test", SHA_STACK_SIZE, NULL, 3, NULL, 0)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -1 \n");
    if(xTaskCreatePinnedToCore(tskAes_Test, "Aes_test", SHA_STACK_SIZE, NULL, 3, NULL, 1)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -2 \n");
    if(xTaskCreatePinnedToCore(tskAesGcm_Test, "AesGcm_test", SHA_STACK_SIZE, NULL, 3, NULL, 0)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -3 \n");
    if(xTaskCreatePinnedToCore(tskAesGcm_Test, "AesGcm_test", SHA_STACK_SIZE, NULL, 3, NULL, 1)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -4 \n");
#endif
#ifdef WOLFSSL_AES_192
    if(xTaskCreatePinnedToCore(tskAes192_Test, "Aes192_test", SHA_STACK_SIZE, NULL, 3, NULL, 0)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -5 \n");
    if(xTaskCreatePinnedToCore(tskAes192_Test, "Aes192_test", SHA_STACK_SIZE, NULL, 3, NULL, 1)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -6 \n");
#endif
#ifdef WOLFSSL_AES_256
    if(xTaskCreatePinnedToCore(tskAes256_Test, "Aes256_test", SHA_STACK_SIZE, NULL, 3, NULL, 0)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -7 \n");
    if(xTaskCreatePinnedToCore(tskAes256_Test, "Aes256_test", SHA_STACK_SIZE, NULL, 3, NULL, 1)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -8 \n");
#endif
#ifdef WOLFSSL_SHA384
    if(xTaskCreatePinnedToCore(tskSha384_Test, "sha384_test", SHA_STACK_SIZE, NULL, 3, NULL, 0)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -13 \n");
    if(xTaskCreatePinnedToCore(tskSha384_Test, "sha384_test", SHA_STACK_SIZE, NULL, 3, NULL, 1)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -14 \n");
#endif
#ifdef WOLFSSL_SHA512
    printf("start sha512\n");
    if(xTaskCreatePinnedToCore(tskSha512_Test, "Sha512_test", SHA_STACK_SIZE, NULL, 3, NULL, 0)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -15 \n");
    if(xTaskCreatePinnedToCore(tskSha512_Test, "Sha512_test", SHA_STACK_SIZE, NULL, 3, NULL, 1)!=pdPASS)
        ESP_LOGE(TAG, "failed to create task -16 \n");

#endif

#else

    exit_semaph = xSemaphoreCreateCounting(num, 0);

#ifndef NO_AES
    xTaskCreate(tskAes_Test, "Aes_test", SHA_STACK_SIZE, NULL, 3, NULL);
    xTaskCreate(tskAesGcm_Test, "AesGcm_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif
#ifdef WOLFSSL_AES_192
    xTaskCreate(tskAes192_Test, "Aes192_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif
#ifdef WOLFSSL_AES_256
    xTaskCreate(tskAes256_Test, "Aes256_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif
#ifndef NO_SHA
    xTaskCreate(tskSha_Test, "Sha_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif
#ifndef NO_SHA256
    xTaskCreate(tskSha256_Test, "sha256_test", SHA_STACK_SIZE, NULL, 3, NULL);
#endif

#endif /* CONFIG_FREERTOS_UNICORE */

    ESP_LOGI(TAG, "Waiting for 15s ...");
    vTaskDelay(15000/portTICK_PERIOD_MS);
    exit_loop = true;


    for(int i=0;i<num;i++){
       if(!xSemaphoreTake(exit_semaph, 2000/portTICK_PERIOD_MS)) {
           TEST_FAIL_MESSAGE("exit semaphore not released by test task");
       }
    }
    vSemaphoreDelete(exit_semaph);
}
