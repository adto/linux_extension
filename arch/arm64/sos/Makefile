# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the sos.
#
subdir-asflags-y += -I$(incdir) \
            -Og
subdir-ccflags-y += -I$(incdir)				\
		    -fno-stack-protector		\
		    -DDISABLE_BRANCH_PROFILING		\
		    $(DISABLE_STACKLEAK_PLUGIN) \
		    -Og \
		    -fno-inline-functions \
			-fno-inline-small-functions \
			-fno-inline-functions-called-once

asflags-y += -Og
ccflags-y += -Og \
		     -fno-inline-functions \
			 -fno-inline-small-functions \
			 -fno-inline-functions-called-once


obj-$(CONFIG_ARM64_SOS) += sos_character_device.o
obj-$(CONFIG_ARM64_SOS) += arm.o
obj-$(CONFIG_ARM64_SOS) += mmu.o
obj-$(CONFIG_ARM64_SOS) += va_layout.o
obj-$(CONFIG_ARM64_SOS) += guest.o
obj-$(CONFIG_ARM64_SOS) += reset.o
obj-$(CONFIG_ARM64_SOS) += reserved_mem.o
obj-$(CONFIG_ARM64_SOS) += pgtable.o
obj-$(CONFIG_ARM64_SOS) += handle_exit.o
obj-$(CONFIG_ARM64_SOS) += tf_if/
obj-$(CONFIG_ARM64_SOS) += hyp/
obj-$(CONFIG_ARM64_SOS) += kernel/