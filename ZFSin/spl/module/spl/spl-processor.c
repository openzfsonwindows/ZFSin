/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 *
 * Copyright (C) 2017 Jorgen Lundman <lundman@lundman.net>
 *
 */

#include <sys/processor.h>
uint32_t
cpu_number(void)
{
	uint32_t cpuid;
	cpuid = (uint32_t)KeGetCurrentProcessorIndex();
	return cpuid % max_ncpus;
	return 0;
	return cpuid >= max_ncpus ? 0 : cpuid;
}

uint32_t
getcpuid()
{
	uint32_t cpuid;
	cpuid = (uint32_t)KeGetCurrentProcessorIndex();
	return cpuid % max_ncpus;
	return 0;
	return cpuid >= max_ncpus ? 0 : cpuid;
}

static uint64_t leaf1_features = 0;
static uint64_t leaf7_features = 0;

uint64_t spl_cpuid_features(void)
{
	static int firsttime = 1;

	if (firsttime) {
		int CPUInfo[4] = { 0 };
		int registers[4] = { 0 };

		firsttime = 0;

		// fetch number of leaf entries
		// CPUInfo[0] has "highest leaf" 
		__cpuid(CPUInfo, 0);

		if (CPUInfo[0] >= 1) {
			__cpuidex(registers, 0x1, 0);
			leaf1_features = ((uint64_t)registers[2]) << 32ULL | registers[3];
		}
		if (CPUInfo[0] >= 7) {
			__cpuidex(registers, 0x7, 0);
			leaf7_features = ((uint64_t)registers[1]) << 32ULL | registers[2];
		}
	}
	return leaf1_features;
}

uint64_t spl_cpuid_leaf7_features(void)
{
	return leaf7_features;
}

// Unsure when these are required? avx only?
static volatile XSTATE_SAVE SaveState;
void kfpu_begin(void)
{
	//VERIFY0(KeSaveExtendedProcessorState(XSTATE_MASK_AVX | XSTATE_MASK_LEGACY_SSE, &SaveState));
}

void kfpu_end(void)
{
	//KeRestoreExtendedProcessorState(&SaveState);
}
