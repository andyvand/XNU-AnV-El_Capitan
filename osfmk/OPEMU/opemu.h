#ifndef OPEMU_H
#define OPEMU_H
#include <stdint.h>

#ifndef TESTCASE
#include <mach/thread_status.h>
#endif

#define __SSEPLUS_CPUID_H__ 1
#define __SSEPLUS_EMULATION_COMPS_SSE3_H__ 1

#include <SSEPlus/SSEPlus_base.h>
#include <SSEPlus/SSEPlus_REF.h>
#include <SSEPlus/SSEPlus_SSE2.h>

#ifndef TESTCASE
/** XNU TRAP HANDLERS **/
unsigned char opemu_ktrap(x86_saved_state_t *state);
void opemu_utrap(x86_saved_state_t *state);
int ssse3_run(uint8_t *instruction, x86_saved_state_t *state, int longmode, int);
int sse3_run(uint8_t *instruction, x86_saved_state_t *state, int longmode, int );
int operands(uint8_t *ModRM, unsigned int hsrc, unsigned int hdst, void *src, void *dst,
				  unsigned int longmode, x86_saved_state_t *saved_state, int kernel_trap, int size_128, int rex, int hsreg, int modbyte, int fisttp);
void storeresult128(uint8_t ModRM, unsigned int hdst, ssp_m128 res);
void storeresult64(uint8_t ModRM, unsigned int hdst, ssp_m64 res);
#endif

void print_bytes(uint8_t *from, int size);

void getxmm(ssp_m128 *v, unsigned int i);
void getmm(ssp_m64 *v, unsigned int i);
void movxmm(ssp_m128 *v, unsigned int i);
void movmm(ssp_m64 *v, unsigned int i);

short fisttps(float *res);
int fisttpl(double *res);
long long fisttpq(long double *res);

#endif