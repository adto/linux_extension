// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 - experimental arm64 sos module
 * Author: Adam Toth <tothadamster@gmail.com>
 */

#ifndef __ARM64_SOS_HYP_SYSCALL_H__
#define __ARM64_SOS_HYP_SYSCALL_H__

typedef enum {
    KERNEL_ENTER,
	KERNEL_EXIT,
	NONE
} sos_syscall_direction_t;

void syscall_dispatcher_fcn(struct kvm_cpu_context * cpu, sos_syscall_direction_t dir);

#endif /* __ARM64_SOS_HYP_SYSCALL_H__ */
