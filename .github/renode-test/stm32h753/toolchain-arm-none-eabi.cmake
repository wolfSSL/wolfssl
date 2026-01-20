set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_CXX_COMPILER arm-none-eabi-g++)
set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)

set(CMAKE_AR arm-none-eabi-ar)
set(CMAKE_RANLIB arm-none-eabi-ranlib)

set(CMAKE_C_STANDARD 11)

set(CPU_FLAGS "-mcpu=cortex-m7 -mthumb -mfpu=fpv5-d16 -mfloat-abi=hard")
set(OPT_FLAGS "-Os -ffunction-sections -fdata-sections")
set(CMSIS_INCLUDES "-I/opt/cmsis-device-h7/Include -I/opt/CMSIS_5/CMSIS/Core/Include -I/opt/firmware")

set(CMAKE_C_FLAGS_INIT "${CPU_FLAGS} ${OPT_FLAGS} ${CMSIS_INCLUDES} -DSTM32H753xx")
set(CMAKE_CXX_FLAGS_INIT "${CPU_FLAGS} ${OPT_FLAGS} ${CMSIS_INCLUDES} -DSTM32H753xx")
set(CMAKE_ASM_FLAGS_INIT "${CPU_FLAGS}")

set(CMAKE_EXE_LINKER_FLAGS_INIT "-Wl,--gc-sections -static")

