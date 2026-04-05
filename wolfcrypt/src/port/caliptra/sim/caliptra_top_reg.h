/* caliptra_top_reg.h — synthesized Caliptra register definitions
 *
 * The RTL-generated caliptra_top_reg.h lives in the Caliptra RTL tree at
 * hw/latest/rtl/src/soc_ifc/rtl/caliptra_top_reg/ which is not distributed
 * in this repository.  This file is a minimal synthesis derived from the
 * Rust register source files:
 *   hw/latest/registers/src/mbox.rs  (generator commit 22ef832b4d3a)
 *   hw/latest/registers/src/soc_ifc.rs
 *
 * Only the constants actually used by caliptra_hwmodel.c are defined here.
 * If the libcaliptra or hw-model example headers are compiled together with
 * this file, place this file first on the include path.
 */

#pragma once

#include <stdint.h>

/* =========================================================================
 * Mailbox (MBOX) block
 *
 * Full APB address:
 *   EXTERNAL_PERIPH_BASE(0x30000000) + CALIPTRA_TOP_REG_MBOX_CSR_BASE_ADDR
 *   + register_offset
 * ========================================================================= */

/* Offset of the MBOX block from EXTERNAL_PERIPH_BASE */
#define CALIPTRA_TOP_REG_MBOX_CSR_BASE_ADDR   0x20000u

/* Register offsets within the MBOX block.
 * Source: mbox.rs — self.ptr.wrapping_add(byte_offset / size_of::<u32>()) */
#define MBOX_CSR_MBOX_LOCK     0x00u /* RO: read to acquire lock */
#define MBOX_CSR_MBOX_USER     0x04u /* RO: AXI USER that holds lock */
#define MBOX_CSR_MBOX_CMD      0x08u /* RW: mailbox command ID */
#define MBOX_CSR_MBOX_DLEN     0x0cu /* RW: data length in bytes */
#define MBOX_CSR_MBOX_DATAIN   0x10u /* WO: write next data word to FIFO */
#define MBOX_CSR_MBOX_DATAOUT  0x14u /* RO: read next data word from FIFO */
#define MBOX_CSR_MBOX_EXECUTE  0x18u /* RW: bit 0 = ring doorbell; write 0 to release */
#define MBOX_CSR_MBOX_STATUS   0x1cu /* RO: status and FSM state */
#define MBOX_CSR_MBOX_UNLOCK   0x20u /* RW (uC only): force unlock */

/* MBOX_LOCK bit.
 * Reading MBOX_LOCK returns 0 if the lock was free (and atomically acquires
 * it), or 1 if the lock was already held by another requester. */
#define MBOX_CSR_MBOX_LOCK_LOCK_MASK               0x01u

/* MBOX_STATUS bits.
 * Source: mbox.rs StatusReadVal::status() → (self.0 >> 0) & 0xf
 *         mbox.rs StatusReadVal::mbox_fsm_ps() → (self.0 >> 6) & 7      */
#define MBOX_CSR_MBOX_STATUS_STATUS_MASK           0x0fu  /* bits [3:0]  */
#define MBOX_CSR_MBOX_STATUS_MBOX_FSM_PS_MASK      0x1c0u /* bits [8:6]  */
#define MBOX_CSR_MBOX_STATUS_MBOX_FSM_PS_LOW       6u     /* shift amount */

/* =========================================================================
 * SOC_IFC / Generic-and-Fuse block
 *
 * Full APB address of a named register:
 *   EXTERNAL_PERIPH_BASE + CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_BASE_ADDR
 *   + register_offset
 *
 * The CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_* constants embed the
 * block base so caliptra_model_apb_write_u32(model, EXTERNAL_PERIPH_BASE +
 * CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_FOO, val) works directly.
 * ========================================================================= */

/* Offset of the SOC_IFC block from EXTERNAL_PERIPH_BASE */
#define CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_BASE_ADDR  0x30000u

/* Full offsets from EXTERNAL_PERIPH_BASE for key control registers.
 * Value = CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_BASE_ADDR + per-register offset.
 * Source: soc_ifc.rs — self.ptr.wrapping_add(byte_offset / size_of::<u32>()) */
#define CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS    0x3003cu
#define CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_FUSE_WR_DONE   0x300b0u
#define CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_BOOTFSM_GO     0x300b8u

/* CPTRA_FLOW_STATUS bit masks.
 * Source: soc_ifc.rs CptraFlowStatusReadVal */
#define GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS_IDEVID_CSR_READY_MASK        0x01000000u
#define GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS_READY_FOR_MB_PROCESSING_MASK 0x10000000u
#define GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS_READY_FOR_RUNTIME_MASK       0x20000000u
#define GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS_READY_FOR_FUSES_MASK         0x40000000u

/* Fuse register offsets (relative to CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_BASE_ADDR).
 * Used with caliptra_fuse_write() helpers that add EXTERNAL_PERIPH_BASE + block base.
 * Source: soc_ifc.rs register block methods.
 * Array sizes from libcaliptra/inc/caliptra_types.h */
#define GENERIC_AND_FUSE_REG_CPTRA_OWNER_PK_HASH_0      0x140u /* [12] u32 */
#define GENERIC_AND_FUSE_REG_FUSE_UDS_SEED_0            0x200u /* [16] u32 */
#define GENERIC_AND_FUSE_REG_FUSE_FIELD_ENTROPY_0       0x240u /* [ 8] u32 */
#define GENERIC_AND_FUSE_REG_FUSE_VENDOR_PK_HASH_0      0x260u /* [12] u32 */
#define GENERIC_AND_FUSE_REG_FUSE_ECC_REVOCATION        0x290u /* [ 1] u32 */
#define GENERIC_AND_FUSE_REG_FUSE_RUNTIME_SVN_0         0x2b8u /* [ 4] u32 */
#define GENERIC_AND_FUSE_REG_FUSE_ANTI_ROLLBACK_DISABLE 0x2c8u /* [ 1] u32 */
#define GENERIC_AND_FUSE_REG_FUSE_IDEVID_CERT_ATTR_0   0x2ccu /* [24] u32 */
#define GENERIC_AND_FUSE_REG_FUSE_IDEVID_MANUF_HSM_ID_0 0x32cu /* [ 4] u32 */
#define GENERIC_AND_FUSE_REG_FUSE_LMS_REVOCATION        0x340u /* [ 1] u32 */
#define GENERIC_AND_FUSE_REG_FUSE_MLDSA_REVOCATION      0x344u /* [ 1] u32 */
#define GENERIC_AND_FUSE_REG_FUSE_SOC_STEPPING_ID       0x348u /* [ 1] u32 */
#define GENERIC_AND_FUSE_REG_FUSE_PQC_KEY_TYPE          0x38cu /* [ 1] u32 */
