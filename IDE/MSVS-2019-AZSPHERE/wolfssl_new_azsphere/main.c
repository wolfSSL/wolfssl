#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include <applibs/log.h>
#include <applibs/gpio.h>
#include <wolfssl/wolfcrypt/settings.h>
#ifndef WOLFSSL_USER_SETTINGS
    #error "user_settings.h not included"
#endif
#include <server.h>
#include <client.h>

// The following #include imports a "template appliance" definition. This app comes with multiple
// implementations of the template appliance, each in a separate directory, which allow the code
// to run unchanged on different hardware.
//
// By default, this app targets hardware that follows the MT3620 Reference Development Board (RDB)
// specification, such as the MT3620 Dev Kit from Seeed Studio.
//
// To target different hardware, you'll need to update CMakeLists.txt.  For example, to target the
// Avnet MT3620 Starter Kit, make this update: azsphere_target_hardware_definition(${PROJECT_NAME}
// TARGET_DIRECTORY "HardwareDefinitions/avnet_mt3620_sk" TARGET_DEFINITION
// "template_appliance.json")
//
// See https://aka.ms/AzureSphereHardwareDefinitions for more details.
#include <hw/template_appliance.h>

/// <summary>
/// Exit codes for this application. These are used for the
/// application exit code. They must all be between zero and 255,
/// where zero is reserved for successful termination.
/// </summary>
typedef enum {
    ExitCode_Success = 0,

    ExitCode_Main_Led = 1
} ExitCode;

int main(void)
{
    Log_Debug(
        "\nVisit https://github.com/Azure/azure-sphere-samples for extensible samples to use as a "
        "starting point for full applications.\n");
    int ret;

    int fd = GPIO_OpenAsOutput(TEMPLATE_LED, GPIO_OutputMode_PushPull, GPIO_Value_High);
    if (fd < 0) {
        Log_Debug(
            "Error opening GPIO: %s (%d). Check that app_manifest.json includes the GPIO used.\n",
            strerror(errno), errno);
        return ExitCode_Main_Led;
    }

    const struct timespec sleepTime = {.tv_sec = 1, .tv_nsec = 0};

    printf("Launching the server...\n");
    ret = azsphere_server_app();
    printf("ret azsphere_server_app = %d\n", ret);

    while (true) {
        GPIO_SetValue(fd, GPIO_Value_Low);
        nanosleep(&sleepTime, NULL);
        GPIO_SetValue(fd, GPIO_Value_High);
        nanosleep(&sleepTime, NULL);
    }
}
