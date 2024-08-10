/* linuxkm_memory.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

#ifdef HAVE_KVMALLOC
/* adapted from kvrealloc() draft by Changli Gao, 2010-05-13 */
void *lkm_realloc(void *ptr, size_t newsize) {
    void *nptr;
    size_t oldsize;

    if (unlikely(newsize == 0)) {
        kvfree(ptr);
        return ZERO_SIZE_PTR;
    }

    if (unlikely(ptr == NULL))
        return kvmalloc_node(newsize, GFP_KERNEL, NUMA_NO_NODE);

    if (is_vmalloc_addr(ptr)) {
        /* no way to discern the size of the old allocation,
         * because the kernel doesn't export find_vm_area().  if
         * it did, we could then call get_vm_area_size() on the
         * returned struct vm_struct.
         */
        return NULL;
    } else {
#ifndef __PIE__
        struct page *page;

        page = virt_to_head_page(ptr);
        if (PageSlab(page) || PageCompound(page)) {
            if (newsize < PAGE_SIZE)
#endif /* ! __PIE__ */
                return krealloc(ptr, newsize, GFP_KERNEL);
#ifndef __PIE__
            oldsize = ksize(ptr);
        } else {
            oldsize = page->private;
            if (newsize <= oldsize)
                return ptr;
        }
#endif /* ! __PIE__ */
    }

    nptr = kvmalloc_node(newsize, GFP_KERNEL, NUMA_NO_NODE);
    if (nptr != NULL) {
        memcpy(nptr, ptr, oldsize);
        kvfree(ptr);
    }

    return nptr;
}
#endif /* HAVE_KVMALLOC */

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
