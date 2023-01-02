// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 - experimental arm64 sos module
 * Author: Adam Toth <tothadamster@gmail.com>
 */

#include <asm/sos_asm.h>
#include <asm/sos_host.h>
#include "sos_sysreg.h"



//DEFINE_PER_CPU(struct kvm_s2_mmu, kvm_s2_mmu);
//struct kvm_s2_mmu *mmu = this_cpu_ptr(&kvm_s2_mmu);
static volatile u64 cntr;

void handle_svc(struct kvm_cpu_context *host_ctxt) {
	u64 hfgitr=0;

	cntr++;

	hfgitr = sos_read_sysreg(SYS_HFGITR_EL2);
	hfgitr |= (u64)HFGITR_EL2_ERET;
	hfgitr &= ~((u64)HFGITR_EL2_SVC_EL0);
	sos_write_sysreg(hfgitr, SYS_HFGITR_EL2);


	return;

}

void handle_eret(struct kvm_cpu_context *host_ctxt) {
	u64 hfgitr=0;

	cntr++;

	hfgitr = sos_read_sysreg(SYS_HFGITR_EL2);
	hfgitr &= ~((u64)HFGITR_EL2_ERET);
	hfgitr |= (u64)HFGITR_EL2_SVC_EL0;
	sos_write_sysreg(hfgitr, SYS_HFGITR_EL2);

	return;
}

int __sos_enter(struct kvm_vcpu *vcpu) {

	u64 hfgitr=0;

	hfgitr = sos_read_sysreg(SYS_HFGITR_EL2);
	hfgitr |= (u64)HFGITR_EL2_SVC_EL0 | (u64)HFGITR_EL2_ERET;
	sos_write_sysreg(hfgitr, SYS_HFGITR_EL2);

	cntr = 10;

	return 0;
}

int __sos_exit(struct kvm_vcpu *vcpu) {

	return 0;
}
