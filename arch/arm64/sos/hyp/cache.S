/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Code copied from arch/arm64/mm/cache.S.
 */

#include <linux/linkage.h>
#include "assembler.h"
#include <asm/alternative.h>

SYM_FUNC_START_PI(__flush_dcache_area)
	//!!!adto: this must be commented out: Dont know why it is not compiling!!!!!
	dcache_by_line_op civac, sy, x0, x1, x2, x3
	ret
SYM_FUNC_END_PI(__flush_dcache_area)
