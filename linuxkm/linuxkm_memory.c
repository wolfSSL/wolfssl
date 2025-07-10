/* linuxkm_memory.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

/* included by wolfcrypt/src/memory.c */

#if defined(__PIE__) && (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
/* needed in 6.1+ because show_free_areas() static definition in mm.h calls
 * __show_free_areas(), which isn't exported (neither was show_free_areas()).
 */
void my__show_free_areas(
    unsigned int flags,
    nodemask_t *nodemask,
    int max_zone_idx)
{
    (void)flags;
    (void)nodemask;
    (void)max_zone_idx;
    return;
}
#endif

#if defined(__PIE__) && defined(CONFIG_FORTIFY_SOURCE)
/* needed because FORTIFY_SOURCE inline implementations call fortify_panic(). */
void __my_fortify_panic(const char *name) {
    pr_emerg("__my_fortify_panic in %s\n", name);
    BUG();
}
#endif
