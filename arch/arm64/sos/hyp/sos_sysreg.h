/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SOS_HYP_SOS_SYSREG_H
#define __SOS_HYP_SOS_SYSREG_H

#include <asm/sysreg.h>

#define sos_read_sysreg(r)					\
	({								\
		u64 reg;						\
		asm volatile(__mrs_s("%0", r)	\
			     : "=r" (reg));				\
		reg;							\
	})

#define sos_write_sysreg(v,r)					\
	do {								\
		u64 __val = (u64)(v);					\
		asm volatile(__msr_s(r, "%x0")	\
					 : : "rZ" (__val));		\
	} while (0)

/* HFGITR_EL2 system register bits */
#define HFGITR_EL2_SVC_EL0 (UL(1) << 52)
#define HFGITR_EL2_ERET    (UL(1) << 51)

#endif /* __SOS_HYP_SOS_SYSREG_H */
