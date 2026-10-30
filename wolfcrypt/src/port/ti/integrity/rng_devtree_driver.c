/* rng_devtree_driver.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Device tree node driver that sets the rng_driver.c register base addresses
 *
 * The relevant device tree nodes (from this board's DTS):
 *
 *   crypto@40900000 {
 *       compatible = "ti,am64-sa2ul";
 *       reg = <0x00 0x40900000 0x00 0x1200>;
 *       power-domains = <0x02 0x85 0x01>;
 *       ...
 *       rng@40910000 {
 *           compatible = "inside-secure,safexcel-eip76";
 *           reg = <0x00 0x40910000 0x00 0x7d>;
 *           interrupts = <0x00 0xa8 0x04>;
 *           clocks = <0x03 0x85 0x00>;
 *       };
 *   };
 */

#include <bsp.h>
#include <INTEGRITY.h>
#include <asp_export.h>
#include <bsp_export.h>
#include <support/memoryspace.h>

#include <devtree.h>

#include <wolfssl/wolfcrypt/port/ti/integrity/rng_driver.h>

static Error RngNodeInit(DevTree_Node Node, const char *MatchName)
{
    Error err;
    DevTree_Node ParentNode;
    Address TrngAddr, TrngSize;
    Address CpAceAddr, CpAceSize;

    (void)MatchName;

    ParentNode = DevTree_Node_GetParent(Node);
    if (ParentNode == NULL) {
        return Failure;
    }

    err = DevTree_Node_GetRegAsKernel(Node, 0, &TrngAddr, &TrngSize);
    if (err != Success) {
        return err;
    }
    err = DevTree_Node_GetRegAsKernel(ParentNode, 0, &CpAceAddr, &CpAceSize);
    if (err != Success) {
        return err;
    }

    rng_driver_set_base((volatile void *)TrngAddr, (volatile void *)CpAceAddr);

    return Success;
}

DevTree_NodeDriver __ghsentry_devtree_node_driver_am64x_rng_node = {
    .name = "AM64x TRNG",
    .supported_types = (const char *[]){
        "inside-secure,safexcel-eip76",
        NULL},
    .init = RngNodeInit,
};
