// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 - experimental arm64 sos module
 * Author: Adam Toth <tothadamster@gmail.com>
 */

#include <asm/sos_asm.h>
#include <asm/sos_host.h>


//DEFINE_PER_CPU(struct kvm_s2_mmu, kvm_s2_mmu);
//struct kvm_s2_mmu *mmu = this_cpu_ptr(&kvm_s2_mmu);

int __sos_enter(struct kvm_vcpu *vcpu) {


	//struct kvm_s2_mmu *mmu = this_cpu_ptr(&kvm_s2_mmu);












	return 0;
}

int __sos_exit(struct kvm_vcpu *vcpu) {

	return 0;
}
