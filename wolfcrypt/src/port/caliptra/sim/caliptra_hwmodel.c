/* caliptra_hwmodel.c — Caliptra hw-model mailbox transport
 *
 * Implements caliptra_mailbox_exec() — the integrator-supplied transport hook
 * declared in caliptra_port.h — using the Caliptra hw-model C binding.
 *
 * Also provides caliptra_hwmodel_init() / caliptra_hwmodel_cleanup() to boot
 * and tear down the emulated hardware before and after test runs.
 *
 * This file is test-only; it is NOT part of the wolfSSL library.
 *
 * Build-time dependencies (set via Makefile -I and -L flags):
 *   caliptra_model.h      — ~/caliptra/hw-model/c-binding/out/
 *   caliptra_top_reg.h    — this directory (wolfcrypt/src/port/caliptra/sim/)
 *   libcaliptra_hw_model_c_binding.a — ~/caliptra/target/debug/
 *
 * Link flags required:
 *   -lpthread -lstdc++ -ldl -lrt -lm
 *
 * Boot files (passed to caliptra_hwmodel_init):
 *   ROM: ~/caliptra/rom/ci_frozen_rom/2.1/caliptra-rom-2.1.0-a72a76f.bin
 *   FW:  ~/caliptra/hw-model/c-binding/out/image_bundle.bin
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* hw-model C binding — provides caliptra_model_init_default, step, apb_read/write */
#include "caliptra_model.h"

/* Synthesized register constants */
#include "caliptra_top_reg.h"

/* Our public interface */
#include "caliptra_hwmodel.h"

/* wolfSSL word32 type (unsigned int on all supported platforms) */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

/* =========================================================================
 * Constants
 * ========================================================================= */

/* Base address of Caliptra peripherals on the APB bus */
#define EXTERNAL_PERIPH_BASE       0x30000000u

/* Boot status value written by the Caliptra runtime when it is ready to
 * accept cryptographic mailbox commands. */
#define RT_READY_FOR_COMMANDS      0x600u

/* Maximum iterations to wait for the mailbox lock before giving up.
 * Each iteration steps the model one clock cycle (~1 ns at 1 GHz).
 * 100 000 steps is generous for simulation. */
#define MBOX_LOCK_MAX_STEPS        100000

/* Mailbox status field values (bits [3:0] of MBOX_CSR_MBOX_STATUS).
 * Source: hw/latest/registers/src/mbox.rs enums::MboxStatusE */
#define MBOX_STATUS_BUSY           0u
#define MBOX_STATUS_DATA_READY     1u
#define MBOX_STATUS_CMD_COMPLETE   2u
#define MBOX_STATUS_CMD_FAILURE    3u

/* Mailbox FSM states (bits [8:6] of MBOX_CSR_MBOX_STATUS).
 * Source: hw/latest/registers/src/mbox.rs enums::MboxFsmE */
#define MBOX_FSM_IDLE              0u

/* =========================================================================
 * Global model handle
 * One model, one thread; no locking.
 * ========================================================================= */
static struct caliptra_model *g_model;

/* =========================================================================
 * Low-level APB register helpers
 * ========================================================================= */

static inline void mbox_write(uint32_t reg_offset, uint32_t val)
{
    uint32_t addr = EXTERNAL_PERIPH_BASE
                  + CALIPTRA_TOP_REG_MBOX_CSR_BASE_ADDR
                  + reg_offset;
    caliptra_model_apb_write_u32(g_model, addr, val);
}

static inline uint32_t mbox_read(uint32_t reg_offset)
{
    uint32_t val = 0;
    uint32_t addr = EXTERNAL_PERIPH_BASE
                  + CALIPTRA_TOP_REG_MBOX_CSR_BASE_ADDR
                  + reg_offset;
    caliptra_model_apb_read_u32(g_model, addr, &val);
    return val;
}

static inline void soc_write(uint32_t reg_offset, uint32_t val)
{
    uint32_t addr = EXTERNAL_PERIPH_BASE
                  + CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_BASE_ADDR
                  + reg_offset;
    caliptra_model_apb_write_u32(g_model, addr, val);
}

/* Write to a register addressed by its full offset from EXTERNAL_PERIPH_BASE
 * (i.e. the CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_* constants). */
static inline void soc_write_direct(uint32_t periph_offset, uint32_t val)
{
    caliptra_model_apb_write_u32(g_model,
                                 EXTERNAL_PERIPH_BASE + periph_offset,
                                 val);
}

/* =========================================================================
 * Mailbox status helpers
 * ========================================================================= */

static inline uint32_t mbox_status(void)
{
    return mbox_read(MBOX_CSR_MBOX_STATUS) & MBOX_CSR_MBOX_STATUS_STATUS_MASK;
}

static inline uint32_t mbox_fsm_state(void)
{
    return (mbox_read(MBOX_CSR_MBOX_STATUS)
            & MBOX_CSR_MBOX_STATUS_MBOX_FSM_PS_MASK)
           >> MBOX_CSR_MBOX_STATUS_MBOX_FSM_PS_LOW;
}

/* =========================================================================
 * Fuse initialisation
 * Writes all zero fuses — valid in debug/unprovisioned mode.
 * ========================================================================= */

static void write_fuse_zeros(uint32_t base_offset, size_t n_words)
{
    for (size_t i = 0; i < n_words; i++)
        soc_write(base_offset + (uint32_t)(i * sizeof(uint32_t)), 0u);
}

static void init_fuses_zero(void)
{
    write_fuse_zeros(GENERIC_AND_FUSE_REG_FUSE_UDS_SEED_0,            16);
    write_fuse_zeros(GENERIC_AND_FUSE_REG_FUSE_FIELD_ENTROPY_0,        8);
    write_fuse_zeros(GENERIC_AND_FUSE_REG_FUSE_VENDOR_PK_HASH_0,      12);
    soc_write(GENERIC_AND_FUSE_REG_FUSE_ECC_REVOCATION,                0);
    write_fuse_zeros(GENERIC_AND_FUSE_REG_CPTRA_OWNER_PK_HASH_0,      12);
    write_fuse_zeros(GENERIC_AND_FUSE_REG_FUSE_RUNTIME_SVN_0,          4);
    soc_write(GENERIC_AND_FUSE_REG_FUSE_ANTI_ROLLBACK_DISABLE,         0);
    write_fuse_zeros(GENERIC_AND_FUSE_REG_FUSE_IDEVID_CERT_ATTR_0,    24);
    write_fuse_zeros(GENERIC_AND_FUSE_REG_FUSE_IDEVID_MANUF_HSM_ID_0,  4);
    soc_write(GENERIC_AND_FUSE_REG_FUSE_LMS_REVOCATION,                0);
    soc_write(GENERIC_AND_FUSE_REG_FUSE_MLDSA_REVOCATION,              0);
    soc_write(GENERIC_AND_FUSE_REG_FUSE_SOC_STEPPING_ID,               0);
    soc_write(GENERIC_AND_FUSE_REG_FUSE_PQC_KEY_TYPE,                  0);
}

/* =========================================================================
 * Mailbox lock acquisition
 * Returns 0 on success, -EBUSY on timeout.
 * ========================================================================= */

static int mbox_acquire_lock(void)
{
    for (int i = 0; i < MBOX_LOCK_MAX_STEPS; i++) {
        /* A read that returns 0 atomically acquires the lock.
         * A read that returns 1 means someone else holds it. */
        uint32_t lock_val = mbox_read(MBOX_CSR_MBOX_LOCK);
        if ((lock_val & MBOX_CSR_MBOX_LOCK_LOCK_MASK) == 0)
            return 0; /* lock acquired */
        caliptra_model_step(g_model);
    }
    fprintf(stderr, "caliptra_hwmodel: mailbox lock timeout\n");
    return -EBUSY;
}

/* =========================================================================
 * Mailbox FIFO write
 * Writes req_len bytes from req into the mailbox DATAIN register word by word.
 * The final partial word (if any) is zero-padded to the right.
 * ========================================================================= */

static void mbox_write_fifo(const void *req, word32 req_len)
{
    const uint8_t *p = (const uint8_t *)req;
    word32 remaining = req_len;

    while (remaining >= 4) {
        uint32_t word;
        memcpy(&word, p, 4);
        mbox_write(MBOX_CSR_MBOX_DATAIN, word);
        p += 4;
        remaining -= 4;
    }
    if (remaining > 0) {
        uint32_t word = 0;
        memcpy(&word, p, remaining);
        mbox_write(MBOX_CSR_MBOX_DATAIN, word);
    }
}

/* =========================================================================
 * Mailbox FIFO read
 * Reads up to resp_len bytes from DATAOUT into resp.
 * resp_dlen is the byte count reported by the hardware (MBOX_DLEN after
 * execute; may be larger or smaller than resp_len).
 * ========================================================================= */

static void mbox_read_fifo(void *resp, word32 resp_len, uint32_t hw_dlen)
{
    uint32_t to_copy = hw_dlen < resp_len ? hw_dlen : resp_len;
    uint8_t *p = (uint8_t *)resp;

    uint32_t full_words = to_copy / 4;
    for (uint32_t i = 0; i < full_words; i++) {
        uint32_t word = mbox_read(MBOX_CSR_MBOX_DATAOUT);
        memcpy(p, &word, 4);
        p += 4;
    }
    uint32_t tail = to_copy % 4;
    if (tail > 0) {
        uint32_t word = mbox_read(MBOX_CSR_MBOX_DATAOUT);
        memcpy(p, &word, tail);
    }

    /* Drain any remaining words the hardware produced but we don't need */
    uint32_t drained = to_copy;
    while (drained + 4 <= hw_dlen) {
        mbox_read(MBOX_CSR_MBOX_DATAOUT);
        drained += 4;
    }
}

/* =========================================================================
 * File loading helper
 * ========================================================================= */

static int load_file(const char *path, struct caliptra_buffer *out)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "caliptra_hwmodel: cannot open '%s': %s\n",
                path, strerror(errno));
        return -errno;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "caliptra_hwmodel: fseek failed on '%s'\n", path);
        fclose(fp);
        return -EIO;
    }
    long sz = ftell(fp);
    if (sz <= 0) {
        fprintf(stderr, "caliptra_hwmodel: '%s' is empty or ftell failed\n", path);
        fclose(fp);
        return -EIO;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -EIO;
    }

    void *buf = malloc((size_t)sz);
    if (!buf) {
        fclose(fp);
        return -ENOMEM;
    }

    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (got != (size_t)sz) {
        fprintf(stderr, "caliptra_hwmodel: short read on '%s': %zu of %ld bytes\n",
                path, got, sz);
        free(buf);
        return -EIO;
    }

    out->data = (const uint8_t *)buf;
    out->len  = (uintptr_t)sz;
    return 0;
}

/* =========================================================================
 * Boot sequence
 * ========================================================================= */

int caliptra_hwmodel_init(const char *rom_path, const char *fw_path)
{
    if (g_model) {
        fprintf(stderr, "caliptra_hwmodel: already initialised\n");
        return -EALREADY;
    }

    /* Load ROM and firmware images */
    struct caliptra_buffer rom = {0};
    struct caliptra_buffer fw  = {0};
    int rc;

    rc = load_file(rom_path, &rom);
    if (rc != 0)
        return rc;

    rc = load_file(fw_path, &fw);
    if (rc != 0) {
        free((void *)rom.data);
        return rc;
    }

    /* Initialise the hw-model.
     * security_state = DBG_UNLOCKED_UNPROVISIONED (0) allows booting with
     * zero fuses in development/simulation environments. */
    uint8_t empty_byte = 0;
    struct caliptra_model_init_params params = {
        .rom            = rom,
        .dccm           = { .data = &empty_byte, .len = 0 },
        .iccm           = { .data = &empty_byte, .len = 0 },
        .security_state = CALIPTRA_SEC_STATE_DBG_UNLOCKED_UNPROVISIONED,
        .soc_user       = 0,
    };

    int init_rc = caliptra_model_init_default(params, &g_model);
    if (init_rc != CALIPTRA_MODEL_STATUS_OK) {
        fprintf(stderr, "caliptra_hwmodel: model init failed (status %d)\n",
                init_rc);
        free((void *)rom.data);
        free((void *)fw.data);
        return -EIO;
    }

    /* Step until the fuse controller is ready */
    while (!caliptra_model_ready_for_fuses(g_model))
        caliptra_model_step(g_model);

    /* Write all-zero fuses (valid in debug/unprovisioned mode) */
    init_fuses_zero();

    /* Signal fuse programming complete */
    soc_write_direct(CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_FUSE_WR_DONE, 1u);

    /* Release the boot FSM */
    soc_write_direct(CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_BOOTFSM_GO, 1u);
    caliptra_model_step(g_model);

    /* Step until the ROM is ready to receive the firmware image */
    while (!caliptra_model_ready_for_fw(g_model))
        caliptra_model_step(g_model);

    /* Upload firmware via mailbox (command FWLD = 0x46574C44) */
    rc = mbox_acquire_lock();
    if (rc != 0) {
        fprintf(stderr, "caliptra_hwmodel: cannot acquire lock for FW upload\n");
        caliptra_model_destroy(g_model);
        g_model = NULL;
        free((void *)rom.data);
        free((void *)fw.data);
        return rc;
    }

    mbox_write(MBOX_CSR_MBOX_CMD,  0x46574C44u); /* "FWLD" */
    mbox_write(MBOX_CSR_MBOX_DLEN, (uint32_t)fw.len);
    mbox_write_fifo(fw.data, (word32)fw.len);
    mbox_write(MBOX_CSR_MBOX_EXECUTE, 1u);

    while (mbox_status() == MBOX_STATUS_BUSY)
        caliptra_model_step(g_model);

    uint32_t upload_status = mbox_status();
    mbox_write(MBOX_CSR_MBOX_EXECUTE, 0u);
    caliptra_model_step(g_model);

    if (upload_status == MBOX_STATUS_CMD_FAILURE) {
        fprintf(stderr, "caliptra_hwmodel: firmware upload returned CMD_FAILURE\n");
        caliptra_model_destroy(g_model);
        g_model = NULL;
        free((void *)rom.data);
        free((void *)fw.data);
        return -EIO;
    }

    /* Step until the runtime signals it is ready for commands */
    caliptra_model_step_until_boot_status(g_model, RT_READY_FOR_COMMANDS);

    free((void *)rom.data);
    free((void *)fw.data);

    fprintf(stderr, "caliptra_hwmodel: runtime ready (boot status 0x%03X)\n",
            RT_READY_FOR_COMMANDS);
    return 0;
}

void caliptra_hwmodel_cleanup(void)
{
    if (g_model) {
        caliptra_model_destroy(g_model);
        g_model = NULL;
    }
}

/* =========================================================================
 * wolfSSL transport hook
 *
 * Called by caliptra_port.c for every cryptographic mailbox operation.
 * The request struct already contains a valid checksum (set by
 * wc_caliptra_req_chksum before this function is called).
 *
 * Returns 0 on success.  Returns a non-zero value if the hardware rejected
 * the command (CMD_FAILURE), the mailbox lock could not be acquired, or the
 * model has not been initialised.
 * ========================================================================= */

int caliptra_mailbox_exec(word32      cmd_id,
                          const void *req,      word32 req_len,
                          void       *resp,     word32 resp_len)
{
    if (!g_model) {
        fprintf(stderr, "caliptra_mailbox_exec: model not initialised\n");
        return -1;
    }

    /* Acquire the mailbox lock */
    int rc = mbox_acquire_lock();
    if (rc != 0)
        return rc;

    /* Write command ID, data length, and request payload */
    mbox_write(MBOX_CSR_MBOX_CMD,  (uint32_t)cmd_id);
    mbox_write(MBOX_CSR_MBOX_DLEN, req_len);
    mbox_write_fifo(req, req_len);

    /* Ring the doorbell */
    mbox_write(MBOX_CSR_MBOX_EXECUTE, 1u);

    /* Step until the firmware has processed the command */
    do {
        caliptra_model_step(g_model);
    } while (mbox_status() == MBOX_STATUS_BUSY);

    uint32_t status = mbox_status();

    if (status == MBOX_STATUS_CMD_FAILURE) {
        mbox_write(MBOX_CSR_MBOX_EXECUTE, 0u);
        caliptra_model_step(g_model);
        fprintf(stderr,
                "caliptra_mailbox_exec: CMD_FAILURE for cmd 0x%08X\n",
                (unsigned)cmd_id);
        return -EIO;
    }

    /* Read response data if the firmware produced any */
    if (status == MBOX_STATUS_DATA_READY && resp != NULL && resp_len > 0) {
        uint32_t hw_dlen = mbox_read(MBOX_CSR_MBOX_DLEN);
        mbox_read_fifo(resp, resp_len, hw_dlen);
    }

    /* Clear execute to release the mailbox lock */
    mbox_write(MBOX_CSR_MBOX_EXECUTE, 0u);

    /* One extra step: the FSM needs a clock edge to return to IDLE after
     * execute is de-asserted (noted in hw-model examples/api/caliptra_api.c). */
    caliptra_model_step(g_model);

    /* Verify the mailbox FSM returned to IDLE */
    uint32_t fsm = mbox_fsm_state();
    if (fsm != MBOX_FSM_IDLE) {
        fprintf(stderr,
                "caliptra_mailbox_exec: FSM not IDLE after cmd 0x%08X"
                " (state %u)\n",
                (unsigned)cmd_id, (unsigned)fsm);
        return -EIO;
    }

    return 0;
}
