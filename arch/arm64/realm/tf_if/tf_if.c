// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 - experimental arm64 realm module
 * Author: Adam Toth <tothadamster@gmail.com>
 */

#include "tf_if.h"

/*
 * Trigger an SMC call.
 */
static void smc_call(const smc_args *args, struct arm_smccc_res *res);

static void smc_call(const smc_args *args, struct arm_smccc_res *res){
	arm_smccc_smc(args->fid,
		      args->arg1,
		      args->arg2,
		      args->arg3,
		      args->arg4,
		      args->arg5,
		      args->arg6,
		      args->arg7,
			  res);
}

u_register_t realm_version(void)
{
	smc_args args = { RMI_RMM_REQ_VERSION };
	struct arm_smccc_res res;

	smc_call(&args, &res);
	return res.a0;
}

u_register_t realm_granule_delegate(u_register_t add)
{
	smc_args args = { 0 };
	struct arm_smccc_res res;

	args.fid = SMC_RMM_GRANULE_DELEGATE;
	args.arg1 = add;

	smc_call(&args, &res);
	return res.a0;
}

u_register_t realm_granule_undelegate(u_register_t add)
{
	smc_args args = { 0 };
	struct arm_smccc_res res;

	args.fid = SMC_RMM_GRANULE_UNDELEGATE;
	args.arg1 = add;

	smc_call(&args, &res);
	return res.a0;
}

u_register_t realm_create(u_register_t rd_addr, u_register_t realm_params_addr)
{
	smc_args args = { 0 };
	struct arm_smccc_res res;

	args.fid = SMC_RMM_REALM_CREATE;
	args.arg1 = rd_addr;
	args.arg2 = realm_params_addr;

	smc_call(&args, &res);
	return res.a0;
}

u_register_t realm_destroy(u_register_t rd_addr)
{
	smc_args args = { 0 };
	struct arm_smccc_res res;

	args.fid = SMC_RMM_REALM_DESTROY;
	args.arg1 = rd_addr;

	smc_call(&args, &res);
	return res.a0;
}
