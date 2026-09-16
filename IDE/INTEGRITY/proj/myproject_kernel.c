#include <INTEGRITY.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef WOLFSSL_SA2UL_DRIVER
#include <wolfssl/wolfcrypt/port/ti/integrity/sa2ul_iodevice_server.h>
#include "myproject_integrate.h"

/* Kernel MemoryRegion Objects can only be resolved from a kernel task, so do it
 * here, once, before any Task can use the "Sa2ulDev" IODevice. */
static void AttachSa2ulSharedPages(void)
{
    Address ctrlFirst, ctrlLast, dataFirst, dataLast;

    if (GetMemoryRegionAddresses(sa2ul_ctrl_phys, &ctrlFirst, &ctrlLast) != Success ||
        GetMemoryRegionAddresses(sa2ul_data_phys, &dataFirst, &dataLast) != Success) {
        printf("sa2ul: shared pages not found; SA2UL offload disabled\n");
        return;
    }
    sa2ul_iodevice_attach_shared_pages((void *)ctrlFirst, ctrlLast - ctrlFirst + 1,
            (void *)dataFirst, dataLast - dataFirst + 1);
}
#endif

int main(void)
{
#ifdef WOLFSSL_SA2UL_DRIVER
    AttachSa2ulSharedPages();
#endif
    printf("Hello world!\n");
    Exit(0);
}
