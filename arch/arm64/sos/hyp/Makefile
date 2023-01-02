# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the sos.
#

asflags-y += -D__KVM_NVHE_HYPERVISOR__ -D__DISABLE_EXPORTS -Og
ccflags-y += -D__KVM_NVHE_HYPERVISOR__ -D__DISABLE_EXPORTS \
			 -fno-stack-protector \
			 -DDISABLE_BRANCH_PROFILING \
			 $(DISABLE_STACKLEAK_PLUGIN) \
			 -Og \
			 -fno-inline-functions \
			 -fno-inline-small-functions \
			 -fno-inline-functions-called-once

hostprogs := gen_hyprel
HOST_EXTRACFLAGS += -I$(objtree)/include

lib-objs := clear_page.o copy_page.o memcpy.o memset.o
lib-objs := $(addprefix ../../lib/, $(lib-objs))

obj-y := cache.o hyp-smp.o  mm.o setup.o hyp_init.o \
 page_alloc.o early_alloc.o switch.o hyp-main.o hyp-entry.o host.o \
 sos.o mem_protect.o tlb.o syscall.o
obj-y += ../pgtable.o
obj-y += $(lib-objs)


##
## Build rules for compiling sos hyp code
## Output of this folder is `sos_hyp.o`, a partially linked object
## file containing all sos hyp code and data.
##

hyp-obj := $(patsubst %.o,%.sos.o,$(obj-y))
obj-y := sos_hyp.o 
extra-y := $(hyp-obj) sos_hyp.tmp.o sos_hyp.rel.o hyp.lds hyp_reloc.S hyp_reloc.o 

# 1) Compile all source files to `.sos.o` object files. The file extension
#    avoids file name clashes
$(obj)/%.sos.o: $(src)/%.c FORCE
	$(call if_changed_rule,cc_o_c)
$(obj)/%.sos.o: $(src)/%.S FORCE
	$(call if_changed_rule,as_o_S)

# 2) Compile linker script.
$(obj)/hyp.lds: $(src)/hyp.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

# 3) Partially link all '.sos.o' files and apply the linker script.
#    Prefixes names of ELF sections with '.hyp', eg. '.hyp.text'.
#    Note: The following rule assumes that the 'ld' rule puts LDFLAGS before
#          the list of dependencies to form '-T $(obj)/hyp.lds'. This is to
#          keep the dependency on the target while avoiding an error from
#          GNU ld if the linker script is passed to it twice.
LDFLAGS_sos_hyp.tmp.o := -r -T
$(obj)/sos_hyp.tmp.o: $(obj)/hyp.lds $(addprefix $(obj)/,$(hyp-obj)) FORCE
	$(call if_changed,ld)

# 4) Generate list of hyp code/data positions that need to be relocated at
#    runtime. Because the hypervisor is part of the kernel binary, relocations
#    produce a kernel VA. We enumerate relocations targeting hyp at build time
#    and convert the kernel VAs at those positions to hyp VAs.
$(obj)/hyp_reloc.S: $(obj)/sos_hyp.tmp.o $(obj)/gen_hyprel
	$(call if_changed,hyprel)	

# 5) Compile hyp_reloc.S and link it into the existing partially linked object.
#    The object file now contains a section with pointers to hyp positions that
#    will contain kernel VAs at runtime. These pointers have relocations on them
#    so that they get updated as the hyp object is linked into `vmlinux`.
LDFLAGS_sos_hyp.rel.o := -r
$(obj)/sos_hyp.rel.o: $(obj)/sos_hyp.tmp.o $(obj)/hyp_reloc.o FORCE
	$(call if_changed,ld)

# 6) Produce the final 'sos_hyp.o', ready to be linked into 'vmlinux'.
#    Prefixes names of ELF symbols with '__sos_hyp_'.
$(obj)/sos_hyp.o: $(obj)/sos_hyp.rel.o FORCE
	$(call if_changed,hypcopy)

# The HYPREL command calls `gen_hyprel` to generate an assembly file with
# a list of relocations targeting hyp code/data.
quiet_cmd_hyprel = HYPREL  $@
      cmd_hyprel = $(obj)/gen_hyprel $< > $@
      
# The HYPCOPY command uses `objcopy` to prefix all ELF symbol names
quiet_cmd_hypcopy = HYPCOPY $@
      cmd_hypcopy = $(OBJCOPY) --prefix-symbols=__sos_hyp_ $< $@      

# Remove ftrace, Shadow Call Stack, and CFI CFLAGS.
# This is equivalent to the 'notrace', '__noscs', and '__nocfi' annotations.
KBUILD_CFLAGS := $(filter-out $(CC_FLAGS_FTRACE) $(CC_FLAGS_SCS) $(CC_FLAGS_CFI), $(KBUILD_CFLAGS))

# sos hyp code is run at a different exception code with a different map, so
# compiler instrumentation that inserts callbacks or checks into the code may
# cause crashes. Just disable it.
GCOV_PROFILE	:= n
KASAN_SANITIZE	:= n
UBSAN_SANITIZE	:= n
KCOV_INSTRUMENT	:= n

# Skip objtool checking for this directory because sos hyp code is compiled with
# non-standard build rules.
OBJECT_FILES_NON_STANDARD := y



		