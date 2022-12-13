// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 - experimental arm64 sos module
 * Author: Adam Toth <tothadamster@gmail.com>
 */

#include <asm/memory.h>
#include <asm/sections.h>
#include <asm/mmu_context.h> //idmap_t0sz
#include <asm/sos_host.h>
#include <asm/sos_mmu.h>
#include <asm/sos_asm.h>
#include <asm/sos_pgtable.h>

static struct kvm_pgtable *hyp_pgtable;
static DEFINE_MUTEX(kvm_hyp_pgd_mutex);

static unsigned long hyp_idmap_start;
static unsigned long hyp_idmap_end;
static phys_addr_t hyp_idmap_vector;

static unsigned long io_map_base;

static void kvm_host_get_page(void *addr)
{
	get_page(virt_to_page(addr));
}

static void *kvm_hyp_zalloc_page(void *arg)
{
	return (void *)get_zeroed_page(GFP_KERNEL);
}

static void kvm_host_put_page(void *addr)
{
	put_page(virt_to_page(addr));
}

static phys_addr_t kvm_host_pa(void *addr)
{
	return __pa(addr);
}

static void *kvm_host_va(phys_addr_t phys)
{
	return __va(phys);
}

phys_addr_t kvm_get_idmap_vector(void)
{
	return hyp_idmap_vector;
}

static phys_addr_t kvm_kaddr_to_phys(void *kaddr)
{
	if (!is_vmalloc_addr(kaddr)) {
		BUG_ON(!virt_addr_valid(kaddr));
		return __pa(kaddr);
	} else {
		return page_to_phys(vmalloc_to_page(kaddr)) +
		       offset_in_page(kaddr);
	}
}

static int __create_hyp_mappings(unsigned long start, unsigned long size,
				 unsigned long phys, enum kvm_pgtable_prot prot)
{
	int err;

//	if (!kvm_host_owns_hyp_mappings()) {
//		return kvm_call_hyp_nvhe(__pkvm_create_mappings,
//					 start, size, phys, prot);
//	}

	mutex_lock(&kvm_hyp_pgd_mutex);
	err = kvm_pgtable_hyp_map(hyp_pgtable, start, size, phys, prot);
	mutex_unlock(&kvm_hyp_pgd_mutex);

	return err;
}


static int __create_hyp_private_mapping(phys_addr_t phys_addr, size_t size,
					unsigned long *haddr,
					enum kvm_pgtable_prot prot)
{
	unsigned long base;
	int ret = 0;

//	if (!kvm_host_owns_hyp_mappings()) {
//		base = kvm_call_hyp_nvhe(__pkvm_create_private_mapping,
//					 phys_addr, size, prot);
//		if (IS_ERR_OR_NULL((void *)base))
//			return PTR_ERR((void *)base);
//		*haddr = base;
//
//		return 0;
//	}

	mutex_lock(&kvm_hyp_pgd_mutex);

	/*
	 * This assumes that we have enough space below the idmap
	 * page to allocate our VAs. If not, the check below will
	 * kick. A potential alternative would be to detect that
	 * overflow and switch to an allocation above the idmap.
	 *
	 * The allocated size is always a multiple of PAGE_SIZE.
	 */
	size = PAGE_ALIGN(size + offset_in_page(phys_addr));
	base = io_map_base - size;

	/*
	 * Verify that BIT(VA_BITS - 1) hasn't been flipped by
	 * allocating the new area, as it would indicate we've
	 * overflowed the idmap/IO address range.
	 */
	if ((base ^ io_map_base) & BIT(VA_BITS - 1))
		ret = -ENOMEM;
	else
		io_map_base = base;

	mutex_unlock(&kvm_hyp_pgd_mutex);

	if (ret)
		goto out;

	ret = __create_hyp_mappings(base, size, phys_addr, prot);
	if (ret)
		goto out;

	*haddr = base + offset_in_page(phys_addr);
out:
	return ret;
}

/**
 * create_hyp_exec_mappings - Map an executable range into HYP
 * @phys_addr:	The physical start address which gets mapped
 * @size:	Size of the region being mapped
 * @haddr:	HYP VA for this mapping
 */
int create_hyp_exec_mappings(phys_addr_t phys_addr, size_t size,
			     void **haddr)
{
	unsigned long addr;
	int ret;

	BUG_ON(is_kernel_in_hyp_mode());

	ret = __create_hyp_private_mapping(phys_addr, size,
					   &addr, PAGE_HYP_EXEC);
	if (ret) {
		*haddr = NULL;
		return ret;
	}

	*haddr = (void *)addr;
	return 0;
}

static struct kvm_pgtable_mm_ops kvm_hyp_mm_ops = {
	.zalloc_page		= kvm_hyp_zalloc_page,
	.get_page		= kvm_host_get_page,
	.put_page		= kvm_host_put_page,
	.phys_to_virt		= kvm_host_va,
	.virt_to_phys		= kvm_host_pa,
};

/**
 * free_hyp_pgds - free Hyp-mode page tables
 */
void free_hyp_pgds(void)
{
	mutex_lock(&kvm_hyp_pgd_mutex);
	if (hyp_pgtable) {
		kvm_pgtable_hyp_destroy(hyp_pgtable);
		kfree(hyp_pgtable);
		hyp_pgtable = NULL;
	}
	mutex_unlock(&kvm_hyp_pgd_mutex);
}

/**
 * create_hyp_mappings - duplicate a kernel virtual address range in Hyp mode
 * @from:	The virtual kernel start address of the range
 * @to:		The virtual kernel end address of the range (exclusive)
 * @prot:	The protection to be applied to this range
 *
 * The same virtual address as the kernel virtual address is also used
 * in Hyp-mode mapping (modulo HYP_PAGE_OFFSET) to the same underlying
 * physical pages.
 */
int create_hyp_mappings(void *from, void *to, enum kvm_pgtable_prot prot)
{
	phys_addr_t phys_addr;
	unsigned long virt_addr;
	unsigned long start = kern_hyp_va((unsigned long)from);
	unsigned long end = kern_hyp_va((unsigned long)to);

	if (is_kernel_in_hyp_mode())
		return 0;

	start = start & PAGE_MASK;
	end = PAGE_ALIGN(end);

	for (virt_addr = start; virt_addr < end; virt_addr += PAGE_SIZE) {
		int err;

		phys_addr = kvm_kaddr_to_phys(from + virt_addr - start);
		err = __create_hyp_mappings(virt_addr, PAGE_SIZE, phys_addr,
					    prot);
		if (err)
			return err;
	}

	return 0;
}

static int kvm_map_idmap_text(void)
{
	unsigned long size = hyp_idmap_end - hyp_idmap_start;
	int err = __create_hyp_mappings(hyp_idmap_start, size, hyp_idmap_start,
					PAGE_HYP_EXEC);
	if (err)
		sos_err("Failed to idmap %lx-%lx\n",
			hyp_idmap_start, hyp_idmap_end);

	return err;
}


int kvm_mmu_init(u32 *hyp_va_bits)
{
	int err;

	hyp_idmap_start = __pa_symbol(__hyp_idmap_text_start);
	hyp_idmap_start = ALIGN_DOWN(hyp_idmap_start, PAGE_SIZE);
	hyp_idmap_end = __pa_symbol(__hyp_idmap_text_end);
	hyp_idmap_end = ALIGN(hyp_idmap_end, PAGE_SIZE);
	hyp_idmap_vector = __pa_symbol(__kvm_hyp_init);

	/*
	 * We rely on the linker script to ensure at build time that the HYP
	 * init code does not cross a page boundary.
	 */
	BUG_ON((hyp_idmap_start ^ (hyp_idmap_end - 1)) & PAGE_MASK);

	*hyp_va_bits = 64 - ((idmap_t0sz & TCR_T0SZ_MASK) >> TCR_T0SZ_OFFSET);
	sos_info("Using %u-bit virtual addresses at EL2\n", *hyp_va_bits);
	sos_info("IDMAP page: %lx\n", hyp_idmap_start);
	sos_info("HYP VA range: %lx:%lx\n",
		  kern_hyp_va(PAGE_OFFSET),
		  kern_hyp_va((unsigned long)high_memory - 1));


	sos_info("__hyp_idmap_text_start: kva:%lx  pha:%lx\n", __hyp_idmap_text_start, __pa_symbol(__hyp_idmap_text_start));
	sos_info("__hyp_idmap_text_end:   kva:%lx  pha:%lx\n", __hyp_idmap_text_end,   __pa_symbol(__hyp_idmap_text_end));
	sos_info("__kvm_hyp_init:         kva:%lx  pha:%lx\n", __kvm_hyp_init,         __pa_symbol(__kvm_hyp_init));

	sos_info("PAGE_OFFSET: kva:%lx hva:%lx\n", PAGE_OFFSET, kern_hyp_va(PAGE_OFFSET));
	sos_info("PHYS_OFFSET: pha:%lx\n", PHYS_OFFSET);
	sos_info("high_memory: kva:%lx hva:%lx\n pha:%lx", ((unsigned long)high_memory), kern_hyp_va((unsigned long)high_memory), __pa((unsigned long)high_memory) );


	if (hyp_idmap_start >= kern_hyp_va(PAGE_OFFSET) &&
	    hyp_idmap_start <  kern_hyp_va((unsigned long)high_memory - 1) &&
	    hyp_idmap_start != (unsigned long)__hyp_idmap_text_start) {
		/*
		 * The idmap page is intersecting with the VA space,
		 * it is not safe to continue further.
		 */
		sos_err("IDMAP intersecting with HYP VA, unable to continue\n");
		err = -EINVAL;
		goto out;
	}

	hyp_pgtable = kzalloc(sizeof(*hyp_pgtable), GFP_KERNEL);
	if (!hyp_pgtable) {
		sos_err("Hyp mode page-table not allocated\n");
		err = -ENOMEM;
		goto out;
	}

	err = kvm_pgtable_hyp_init(hyp_pgtable, *hyp_va_bits, &kvm_hyp_mm_ops);
	if (err)
		goto out_free_pgtable;

	err = kvm_map_idmap_text();
	if (err)
		goto out_destroy_pgtable;

	io_map_base = hyp_idmap_start;
	return 0;

out_destroy_pgtable:
	kvm_pgtable_hyp_destroy(hyp_pgtable);
out_free_pgtable:
	kfree(hyp_pgtable);
	hyp_pgtable = NULL;
out:
	return err;
}

phys_addr_t kvm_mmu_get_httbr(void)
{
	return __pa(hyp_pgtable->pgd);
}

