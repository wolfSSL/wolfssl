/* caliptra_hwmodel.h — hw-model backend for the wolfSSL Caliptra port
 *
 * Declares the lifecycle functions that must be called before and after
 * using the Caliptra mailbox transport via caliptra_mailbox_exec().
 *
 * Typical usage:
 *
 *   caliptra_hwmodel_init(ROM_PATH, FW_PATH);   // boot the model
 *   wc_CryptoCb_RegisterDevice(WOLF_CALIPTRA_DEVID, wc_caliptra_cb, NULL);
 *   ... run wolfSSL operations ...
 *   caliptra_hwmodel_cleanup();                 // destroy the model
 *
 * This file is test-only; it is not part of the wolfSSL library.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Boot the Caliptra hw-model emulator.
 *
 * Loads ROM from rom_path, firmware from fw_path, initialises the hw-model,
 * writes zero fuses (debug/unprovisioned mode), releases boot FSM, uploads
 * firmware, and steps the model until the runtime is ready to accept
 * cryptographic mailbox commands (boot status 0x600).
 *
 * Returns 0 on success, negative errno on failure.
 * Calling init when already initialised returns -EALREADY.
 */
int caliptra_hwmodel_init(const char *rom_path, const char *fw_path);

/* Destroy the hw-model and release all resources.
 *
 * Safe to call if init was never called or already failed.
 */
void caliptra_hwmodel_cleanup(void);

#ifdef __cplusplus
}
#endif
