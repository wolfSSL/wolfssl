# WolfSSL Examples using the OM13076 (LPCXpresso18S37) board

To use, install the NXP LPCXpresso IDE and import the projects in a new workspace.

1. Run LPCXpresso and choose a workspace location.
2. Right click in the project exporer window and choose Inport.
3. Under General choose "Existing Projects into Workspace".
4. Under "Select root directory" click browse and select the wolfSSL root.
5. You should see "lib_wolfssl" under "Projects:".
6. Click finish.
7. Repeat the process but for step 4 choose "IDE/LPCXPRESSO" as the folder.
8. Import the "wolf_demo", "lpc_board_nxp_lpcxpresso_1837" and "lpc_chip_18xx" projects.


## WolfSSL example projects:

1. `wolf_demo` based on the `periph_aes` example. It has console options to run the Wolf tests and benchmarks ('t' for the WolfSSL Tests and 'b' for the WolfSSL Benchmarks).

## Static libraries projects:

1. `wolfssl` for WolfSSL. The WolfSSL port for the LPC18XX platform is located in `IDE/LPCXPRESSO/lpc_18xx_port.c`. This has port functions for `current_time` and `rand_gen`. The `WOLF_USER_SETTINGS` define is set which allows all WolfSSL settings to exist in the `user_settings.h` file (see this file for all customizations set).

## Important Files

1. `IDE/LPCXPRESSO/user_settings.h`. This provides a reference for library settings used to optimize for this embedded platform.

2. `IDE/LPCXPRESSO/lpc_18xx_port.c`. This defines the required time and random number functions for the WolfSSL library.

3. `IDE/LPCXPRESSO/wolf_demo/aes.c`. This shows use of the WolfSSL tests and benchmarks. It also is their example driver for using their AES HW acceleration, which would be the next step for integration into the WolfSSL library.
