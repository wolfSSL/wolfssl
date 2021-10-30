#include "sce_tst_thread.h"
#include "user_settings.h"
/* sce_tst_thread entry function */
/* pvParameters contains TaskHandle_t */

int sce_test();

void sce_tst_thread_entry(void *pvParameters)
{
    FSP_PARAMETER_NOT_USED (pvParameters);

    /* TODO: add your own code here */
    sce_test();
    while (1)
    {
        vTaskDelay (1);
    }
}
