#include "RTOS.h"
#include "BSP.h"
#include <wolfcrypt/benchmark/benchmark.h>

static OS_STACKPTR int WLFSTACK[20000];   /* Stack Size */
static OS_TASK WLFTASK;         /* Task-control-blocks */

static void wolfTask(void) {
  benchmark_test(NULL);
  while (1) {
    BSP_ToggleLED(1);
    OS_Delay(200);
  }
}

/*********************************************************************
*
*       main()
*/
int main(void) {
  OS_IncDI();                      /* Initially disable interrupts  */
  OS_InitKern();                   /* Initialize OS                 */
  OS_InitHW();                     /* Initialize Hardware for OS    */
  BSP_Init();                      /* Initialize LED ports          */
  /* You need to create at least one task before calling OS_Start() */
  OS_CREATETASK(&WLFTASK, "Tests task", wolfTask, 100, WLFSTACK);
  OS_Start();                      /* Start multitasking            */
  return 0;
}

/****** End Of File *************************************************/
