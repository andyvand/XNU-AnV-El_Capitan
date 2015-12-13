/*   ** SINETEK **
 * This is called the Opcode Emulator: it traps invalid opcode exceptions
 *   and modifies the state of the running thread accordingly.
 * There are two entry points, one for user space exceptions, and another for
 *   exceptions coming from kernel space.
 *
 * STATUS
 *  . SSE3 is implemented.
 *  . SSSE3 is implemented.
 *  . SYSENTER is implemented.
 *  . SYSEXIT is implemented.
 *  . RDMSR is implemented.
 *  . Vector register save and restore is implemented.
 *
 * This is a new version of AnV Software based on the AMD SSEPlus project
 * It runs much more reliable and much faster
 */

#define __SSEPLUS_NATIVE_SSE2_H__ 1
#define __SSEPLUS_EMULATION_SSE2_H__ 1
#define __SSEPLUS_ARITHMETIC_SSE2_H__ 1

#include <stdint.h>

#include "opemu.h"
#include "opemu_math.h"

#include <SSEPlus/SSEPlus_Base.h>
#include <SSEPlus/SSEPlus_REF.h>

#ifndef TESTCASE
#include <kern/sched_prim.h>

#define EMULATION_FAILED -1

// forward declaration for syscall handlers of mach/bsd (32+64 bit);
extern void mach_call_munger(x86_saved_state_t *state);
extern void unix_syscall(x86_saved_state_t *);
extern void mach_call_munger64(x86_saved_state_t *state);
extern void unix_syscall64(x86_saved_state_t *);

// forward declaration of panic handler for kernel traps;
extern void panic_trap(x86_saved_state64_t *regs);

// AnV - Implemented i386 version
#ifdef __x86_64__
unsigned char opemu_ktrap(x86_saved_state_t *state)
{
    x86_saved_state64_t *saved_state = saved_state64(state);
    
    uint8_t *code_buffer = (uint8_t *)saved_state->isf.rip;
    unsigned int bytes_skip = 0;
    
    
    bytes_skip = ssse3_run(code_buffer, state, 1, 1);
    
    if (!bytes_skip)
    {
        bytes_skip = sse3_run_a(code_buffer, state, 1, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = sse3_run_b(code_buffer, state, 1, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = sse3_run_c(code_buffer, state, 1, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = fisttp_run(code_buffer, state, 1, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = monitor_mwait_run(code_buffer, state, 1, 1);
    }
    
    if(!bytes_skip)
    {
        /* since this is ring0, it could be an invalid MSR read.
         * Instead of crashing the whole machine, report on it and keep running. */
        if((code_buffer[0]==0x0f) && (code_buffer[1]==0x32))
        {
            printf("[MSR] unknown location 0x%016llx\r\n", saved_state->rcx);
            // best we can do is return 0;
            saved_state->rdx = saved_state->rax = 0;
            bytes_skip = 2;
        }
    }
    
    saved_state->isf.rip += bytes_skip;
    
    if(!bytes_skip)
    {
        uint8_t *ripptr = (uint8_t *)&(saved_state->isf.rip);
        printf("invalid kernel opcode (64-bit): ");
        print_bytes(ripptr, 16);
        
        /* Fall through to trap */
        return 0;
    }

    return 1;
}
#else
unsigned char opemu_ktrap(x86_saved_state_t *state)
{
    x86_saved_state32_t *saved_state = saved_state32(state);
    uint64_t op = saved_state->eip;
    uint8_t *code_buffer = (uint8_t*)op ;
    unsigned int bytes_skip = 0;
    
    
    bytes_skip = ssse3_run(code_buffer, state, 0, 1);
    
    if (!bytes_skip)
    {
        bytes_skip = sse3_run_a(code_buffer, state, 0, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = sse3_run_b(code_buffer, state, 0, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = sse3_run_c(code_buffer, state, 0, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = fisttp_run(code_buffer, state, 0, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = monitor_mwait_run(code_buffer, state, 0, 1);
    }
    
    if(!bytes_skip)
    {
        /* since this is ring0, it could be an invalid MSR read.
         * Instead of crashing the whole machine, report on it and keep running. */
        if(code_buffer[0]==0x0f && code_buffer[1]==0x32)
        {
            printf("[MSR] unknown location 0x%016llx\r\n", saved_state->ecx);
            
            // best we can do is return 0;
            saved_state->edx = saved_state->eax = 0;
            bytes_skip = 2;
        }
    }
    
    saved_state->eip += bytes_skip;
    
    if(!bytes_skip)
    {
        uint8_t *eipptr = (uint8_t *)&(saved_state->eip);
        
        printf("invalid kernel opcode (32-bit): ");
        print_bytes(eipptr, 16);
        
        /* Fall through to trap */
        return 0;
    }
    
    return 1;
}
#endif

void opemu_utrap(x86_saved_state_t *state)
{
    
    int longmode;
    
    unsigned int bytes_skip = 0;
    vm_offset_t addr;
    
    if ((longmode = is_saved_state64(state)))
    {
        
        x86_saved_state64_t *saved_state = saved_state64(state);
        uint8_t *code_buffer = (uint8_t*)saved_state->isf.rip;
        
        addr = saved_state->isf.rip;
        uint16_t opcode;
        
        opcode = *(uint16_t *) addr;
        
        x86_saved_state64_t *regs;
        regs = saved_state64(state);
        if (opcode == 0x340f)
        {
            regs->isf.rip = regs->rdx;
            regs->isf.rsp = regs->rcx;
            
            if((signed int)regs->rax < 0) {
                //printf("mach call 64\n");
                mach_call_munger64(state);
            } else {
                //printf("unix call 64\n");
                unix_syscall64(state);
            }
            return;
        }
        
        if (opcode == 0x350f)
        {
            regs->isf.rip = regs->rdx;
            regs->isf.rsp = regs->rcx;
            //if (kernel_trap)
            //{
            //  addr = regs->rcx;
            //  return 0x7FFF;
            //} else {
            thread_exception_return();
            //}
            return;
        }
        
        bytes_skip = ssse3_run(code_buffer, state, longmode, 0);
        
        if (!bytes_skip)
        {
            bytes_skip = sse3_run_a(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = sse3_run_b(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = sse3_run_c(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = fisttp_run(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = monitor_mwait_run(code_buffer, state, longmode, 0);
        }
        
        regs->isf.rip += bytes_skip;
        
        if(!bytes_skip) {
            uint8_t *ripptr = (uint8_t *)&(regs->isf.rip);
            
            printf("invalid user opcode 64: ");
            print_bytes(ripptr, 16);

            /* Fall through to trap */
            return;
        }
    } else {
        x86_saved_state32_t *saved_state = saved_state32(state);
        uint64_t op = saved_state->eip;
        uint8_t *code_buffer = (uint8_t*)op;
        
        addr = saved_state->eip;
        uint16_t opcode;
        
        opcode = *(uint16_t *) addr;
        
        x86_saved_state32_t *regs;
        regs = saved_state32(state);
        
        /*if (opcode == 0x340f)
        {
            regs->eip = regs->edx;
            regs->uesp = regs->ecx;
            
            if((signed int)regs->eax < 0) {
                mach_call_munger(state);
            } else {
                unix_syscall(state);
            }
            return;
            
        }*/
        
        if (opcode == 0x350f)
        {
            regs->eip = regs->edx;
            regs->uesp = regs->ecx;
            
            thread_exception_return();
            
            return;
        }
        
        bytes_skip = ssse3_run(code_buffer, state, longmode, 0);
        
        if (!bytes_skip)
        {
            bytes_skip = sse3_run_a(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = sse3_run_b(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = sse3_run_c(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = fisttp_run(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = monitor_mwait_run(code_buffer, state, longmode, 0);
        }
        
        regs->eip += bytes_skip;
        
        if(!bytes_skip) {
            uint8_t *eipptr = (uint8_t *)&(regs->eip);
            
            printf("invalid user opcode 32: ");
            print_bytes(eipptr, 16);
            
            /* Fall through to trap */
            return;
        }
        
    }
    
    thread_exception_return();
    /*** NOTREACHED ***/
    
    //EMULATION_FAILED;
}

/** Runs the sse3 emulator. returns the number of bytes consumed.
 **/
int sse3_run_a(uint8_t *instruction, x86_saved_state_t *state, int longmode, int kernel_trap)
{
    uint8_t *bytep = instruction;
    int ins_size = 0;
    ssp_m128 xmmsrc, xmmdst, xmmres;
    int src_higher = 0, dst_higher = 0;
    
    if(*bytep != 0xF2) return 0;
    
    bytep++;
    ins_size++;
    
    if(*bytep != 0x0f) return 0;
    bytep++;
    ins_size++;
    
    uint8_t *modrm = &bytep[1];
    ins_size += 1;
    int consumed = fetchoperands(modrm, src_higher, dst_higher, &xmmsrc, &xmmdst, longmode, state, kernel_trap, 1, ins_size);
    ins_size += consumed;

    switch (*bytep)
    {
        case 0x12:
            //movddup(&xmmsrc,&xmmres);
            xmmres.d = ssp_movedup_pd_REF(xmmsrc.d);
            break;

        case 0x7C:
            //haddps(&xmmsrc,&xmmdst,&xmmres);
            xmmres.f = ssp_hadd_ps_REF(xmmdst.f, xmmsrc.f);
            break;

        case 0x7D:
            //hsubps(&xmmsrc,&xmmdst,&xmmres);
            xmmres.f = ssp_hsub_ps_REF(xmmdst.f, xmmsrc.f);
            break;

        case 0xD0:
            //addsubps(&xmmsrc,&xmmdst,&xmmres);
            xmmres.f = ssp_addsub_ps_REF(xmmdst.f, xmmsrc.f);
            break;

        case 0xF0:
            //lddqu(&xmmsrc,&xmmres);
            xmmres.i = ssp_lddqu_si128_REF(&xmmsrc.i);
            break;

        default:
            return 0;
    }

    storeresult128(*modrm, dst_higher, xmmres);
    
    return ins_size;
}

int sse3_run_b(uint8_t *instruction, x86_saved_state_t *state, int longmode, int kernel_trap)
{
    uint8_t *bytep = instruction;
    int ins_size = 0;
    ssp_m128 xmmsrc, xmmdst, xmmres;
    int src_higher = 0, dst_higher = 0;
    
    if(*bytep != 0xF3) return 0;
    
    bytep++;
    ins_size++;
    
    if(*bytep != 0x0f) return 0;
    bytep++;
    ins_size++;
    
    uint8_t *modrm = &bytep[1];
    ins_size += 1;
    int consumed = fetchoperands(modrm, src_higher, dst_higher, &xmmsrc, &xmmdst, longmode, state, kernel_trap, 1, ins_size);
    ins_size += consumed;

    switch (*bytep)
    {
        case 0x12:
            //movsldup(&xmmsrc,&xmmres);
            xmmres.f = ssp_moveldup_ps_REF(xmmsrc.f);
            break;

        case 0x16:
            //movshdup(&xmmsrc,&xmmres);
            xmmres.f = ssp_movehdup_ps_REF(xmmsrc.f);
            break;

        default:
            return 0;
    }

    storeresult128(*modrm, dst_higher, xmmres);
    
    return ins_size;
}

int sse3_run_c(uint8_t *instruction, x86_saved_state_t *state, int longmode, int kernel_trap)
{
    uint8_t *bytep = instruction;
    int ins_size = 0;
    ssp_m128 xmmsrc, xmmdst, xmmres;
    int src_higher = 0, dst_higher = 0;
    
    if(*bytep != 0x66) return 0;
    
    bytep++;
    ins_size++;
    
    if(*bytep != 0x0f) return 0;
    bytep++;
    ins_size++;
    
    uint8_t *modrm = &bytep[1];
    ins_size += 1;
    int consumed = fetchoperands(modrm, src_higher, dst_higher, &xmmsrc, &xmmdst, longmode, state, kernel_trap, 1, ins_size);
    ins_size += consumed;

    switch (*bytep)
    {
        case 0x7C:
            //haddpd(&xmmsrc,&xmmdst,&xmmres);
            xmmres.d = ssp_hadd_pd_REF(xmmdst.d, xmmsrc.d);
            break;

        case 0x7D:
            //hsubpd(&xmmsrc,&xmmdst,&xmmres);
            xmmres.d = ssp_hsub_pd_REF(xmmdst.d, xmmsrc.d);
            break;

        case 0xD0:
            //addsubpd(&xmmsrc,&xmmdst,&xmmres);
            xmmres.d = ssp_addsub_pd_REF(xmmdst.d, xmmsrc.d);
            break;

        default:
            return 0;
    }

    storeresult128(*modrm, dst_higher, xmmres);
    
    return ins_size;
}

int fisttp_run(uint8_t *instruction, x86_saved_state_t *state, int longmode, int __unused kernel_trap)
{
    uint8_t *bytep = instruction;
    int ins_size = 0;
    uint8_t base = 0;
    uint8_t mod = 0;
    int8_t add = 0;
    uint8_t modrm = 0;
    uint64_t address = 0;
    uint64_t reg_sel[8];
    
    if (longmode)
    {
        x86_saved_state64_t* r64 = saved_state64(state);
        reg_sel[0] = r64->rax;
        reg_sel[1] = r64->rcx;
        reg_sel[2] = r64->rdx;
        reg_sel[3] = r64->rbx;
        reg_sel[4] = r64->isf.rsp;
        reg_sel[5] = r64->rbp;
        reg_sel[6] = r64->rsi;
        reg_sel[7] = r64->rdi;
    } else {
        x86_saved_state32_t* r32 = saved_state32(state);
        reg_sel[0] = r32->eax;
        reg_sel[1] = r32->ecx;
        reg_sel[2] = r32->edx;
        reg_sel[3] = r32->ebx;
        reg_sel[4] = r32->uesp;
        reg_sel[5] = r32->ebp;
        reg_sel[6] = r32->esi;
        reg_sel[7] = r32->edi;
    }
    
    if (*bytep == 0x66)
    {
        bytep++;
        ins_size++;
    }
    
    switch (*bytep)
    {
        case 0xDB:
        {
            bytep++;
            ins_size++;
            
            modrm = *bytep;
            base = modrm & 0x7;
            mod = (modrm & 0xC0) >> 6;
            
            if (mod == 0)
            {
                address = reg_sel[base];
            } else if (mod == 1) {
                bytep++;
                ins_size++;
                
                add = *bytep;
                address = reg_sel[base] + add;
            } else {
                return 0;
            }
            
            *(int *)address = fisttpl((double *)address);

            ins_size++;
            
            return(ins_size);
        }

        case 0xDD:
        {
            bytep++;
            ins_size++;
            
            modrm = *bytep;
            base = modrm & 0x7;
            mod = (modrm & 0xC0) >> 6;
            
            if (mod == 0)
            {
                address = reg_sel[base];
            } else if (mod == 1) {
                bytep++;
                ins_size++;
                
                add = *bytep;
                address = reg_sel[base] + add;
            } else {
                return 0;
            }
            
            *(long long *)address = fisttpq((long double *)address);
            
            ins_size++;
            
            return(ins_size);
        }

        case 0xDF:
        {
            bytep++;
            ins_size++;
            
            modrm = *bytep;
            base = modrm & 0x7;
            mod = (modrm & 0xC0) >> 6;
            
            if (mod == 0)
            {
                address = reg_sel[base];
            } else if (mod == 1) {
                bytep++;
                ins_size++;
                
                add = *bytep;
                address = reg_sel[base] + add;
            } else {
                return 0;
            }
            
            *(short *)address = fisttps((float *)address);
            
            ins_size++;
            
            return(ins_size);
        }
    }
    
    return 0;
}

int monitor_mwait_run(uint8_t *instruction, __unused x86_saved_state_t *  state, int __unused longmode, int __unused kernel_trap)
{
    uint8_t *bytep = instruction;
    
    if (*bytep != 0x0F)
    {
        return 0;
    }
    
    bytep++;
    
    if (*bytep != 0x01)
    {
        return 0;
    }
    
    bytep++;
    
    switch(*bytep)
    {
        case 0xC8:
        case 0xC9:
            return 3;
    }
    
    return 0;
}

const int palignr_getimm128(const unsigned char *bytep)
{
    int rv = 0;
    uint8_t modrm = bytep[4];
    
    if (modrm < 0x40)
    {
        rv = (int)bytep[5];
    } else if (modrm < 0x80) {
        rv = (int)bytep[6];
    } else if (modrm < 0xC0) {
        rv = (int)bytep[9];
    } else {
        rv = (int)bytep[5];
    }
    
    return (const int)rv;
}

const int palignr_getimm64(const unsigned char *bytep)
{
    int rv = 0;
    uint8_t modrm = bytep[3];
    
    if (modrm < 0x40)
    {
        rv = (int)bytep[4];
    } else if (modrm < 0x80) {
        rv = (int)bytep[5];
    } else if (modrm < 0xC0) {
        rv = (int)bytep[8];
    } else {
        rv = (int)bytep[4];
    }
    
    return (const int)rv;
}

/** Runs the ssse3 emulator. returns the number of bytes consumed.
 **/
int ssse3_run(uint8_t *instruction, x86_saved_state_t *state, int longmode, int kernel_trap)
{
    // pointer to the current byte we're working on
    uint8_t *bytep = instruction;
    int ins_size = 0;
    int is_128 = 0, src_higher = 0, dst_higher = 0;
    
    
    ssp_m128 xmmsrc, xmmdst, xmmres;
    ssp_m64 mmsrc,mmdst, mmres;
    
    
    /** We can get a few prefixes, in any order:
     **  66 throws into 128-bit xmm mode.
     **  40->4f use higher xmm registers.
     **/
    if(*bytep == 0x66) {
        is_128 = 1;
        bytep++;
        ins_size++;
    }
    if((*bytep & 0xF0) == 0x40) {
        if(*bytep & 1) src_higher = 1;
        if(*bytep & 4) dst_higher = 1;
        bytep++;
        ins_size++;
    }
    
    if(*bytep != 0x0f) return 0;
    bytep++;
    ins_size++;
    
    /* Two SSSE3 instruction prefixes. */
    if((*bytep == 0x38 && bytep[1] != 0x0f) || (*bytep == 0x3a && bytep[1] == 0x0f)) {
        uint8_t opcode = bytep[1];
        uint8_t *modrm = &bytep[2];
        uint8_t operand;
        ins_size += 2; // not counting modRM byte or anything after.
        
        if(is_128) {
            int consumed = fetchoperands(modrm, src_higher, dst_higher, &xmmsrc, &xmmdst, longmode, state, kernel_trap, 1, ins_size);
            operand = bytep[2 + consumed];
            ins_size += consumed;

            switch(opcode) {
                case 0x00:
                    //pshufb128(&xmmsrc,&xmmdst,&xmmres);
                    xmmres.i = ssp_shuffle_epi8_REF(xmmdst.i, xmmsrc.i);
                    break;

                case 0x01:
                    //phaddw128(&xmmsrc,&xmmdst,&xmmres);
                    xmmres.i = ssp_hadd_epi16_REF(xmmdst.i, xmmsrc.i);
                    break;

                case 0x02:
                    //phaddd128(&xmmsrc,&xmmdst,&xmmres);
                    xmmres.i = ssp_hadd_epi32_REF(xmmdst.i, xmmsrc.i);
                    break;

                case 0x03:
                    //phaddsw128(&xmmsrc,&xmmdst,&xmmres);
                    xmmres.i = ssp_hadds_epi16_REF(xmmdst.i, xmmsrc.i);
                    break;

                case 0x04:
                    //pmaddubsw128(&xmmsrc,&xmmdst,&xmmres);
                    xmmres.i = ssp_maddubs_epi16_REF(xmmdst.i, xmmsrc.i);
                    break;

                case 0x05:
                    //phsubw128(&xmmsrc,&xmmdst,&xmmres);
                    xmmres.i = ssp_hsub_epi16_REF(xmmdst.i, xmmsrc.i);
                    break;

                case 0x06:
                    //phsubd128(&xmmsrc,&xmmdst,&xmmres);
                    xmmres.i = ssp_hsub_epi32_REF(xmmdst.i, xmmsrc.i);
                    break;

                case 0x07:
                    //phsubsw128(&xmmsrc,&xmmdst,&xmmres);
                    xmmres.i = ssp_hsubs_epi16_REF(xmmdst.i, xmmsrc.i);
                    break;

                case 0x08:
                    //psignb128(&xmmsrc,&xmmdst,&xmmres);
                    xmmres.i = ssp_sign_epi8_REF(xmmdst.i, xmmsrc.i);
                    break;

                case 0x09:
                    //psignw128(&xmmsrc,&xmmdst,&xmmres);
                    xmmres.i = ssp_sign_epi16_REF(xmmdst.i, xmmsrc.i);
                    break;

                case 0x0A:
                    //psignd128(&xmmsrc,&xmmdst,&xmmres);
                    xmmres.i = ssp_sign_epi32_REF(xmmdst.i, xmmsrc.i);
                    break;

                case 0x0B:
                    //pmulhrsw128(&xmmsrc,&xmmdst,&xmmres);
                    xmmres.i = ssp_mulhrs_epi16_REF(xmmdst.i, xmmsrc.i);
                    break;

                case 0x0F:
                    //palignr128(&xmmsrc,&xmmdst,&xmmres,(const int)operand);
                    xmmres.i = ssp_alignr_epi8_REF(xmmdst.i, xmmsrc.i, palignr_getimm128(bytep));
                    ins_size++;
                    break;

                case 0x1C:
                    //pabsb128(&xmmsrc,&xmmres);
                    xmmres.i = ssp_abs_epi8_REF(xmmsrc.i);
                    break;

                case 0x1D:
                    //pabsw128(&xmmsrc,&xmmres);
                    xmmres.i = ssp_abs_epi16_REF(xmmsrc.i);
                    break;

                case 0x1E:
                    //pabsd128(&xmmsrc,&xmmres);
                    xmmres.i = ssp_abs_epi32_REF(xmmsrc.i);
                    break;

                default:
                    return 0;
            }

            storeresult128(*modrm, dst_higher, xmmres);
        } else {
            int consumed = fetchoperands(modrm, src_higher, dst_higher, &mmsrc, &mmdst, longmode, state, kernel_trap, 0, ins_size);
            operand = bytep[2 + consumed];
            ins_size += consumed;

            switch(opcode) {
                case 0x00:
                    //pshufb64(&mmsrc,&mmdst,&mmres);
                    mmres.m64 = ssp_shuffle_pi8_REF(mmdst.m64, mmsrc.m64);
                    break;

                case 0x01:
                    //phaddw64(&mmsrc,&mmdst,&mmres);
                    mmres.m64 = ssp_hadd_pi16_REF(mmdst.m64, mmsrc.m64);
                    break;

                case 0x02:
                    //phaddd64(&mmsrc,&mmdst,&mmres);
                    mmres.m64 = ssp_hadd_pi32_REF(mmdst.m64, mmsrc.m64);
                    break;

                case 0x03:
                    //phaddsw64(&mmsrc,&mmdst,&mmres);
                    mmres.m64 = ssp_hadds_pi16_REF(mmdst.m64, mmsrc.m64);
                    break;

                case 0x04:
                    //pmaddubsw64(&mmsrc,&mmdst,&mmres);
                    mmres.m64 = ssp_maddubs_pi16_REF(mmdst.m64, mmsrc.m64);
                    break;

                case 0x05:
                    //phsubw64(&mmsrc,&mmdst,&mmres);
                    mmres.m64 = ssp_hsub_pi16_REF(mmdst.m64, mmsrc.m64);
                    break;

                case 0x06:
                    //phsubd64(&mmsrc,&mmdst,&mmres);
                    mmres.m64 = ssp_hsub_pi32_REF(mmdst.m64, mmsrc.m64);
                    break;

                case 0x07:
                    //phsubsw64(&mmsrc,&mmdst,&mmres);
                    mmres.m64 = ssp_hsubs_pi16_REF(mmdst.m64, mmsrc.m64);
                    break;

                case 0x08:
                    //psignb64(&mmsrc,&mmdst,&mmres);
                    mmres.m64 = ssp_sign_pi8_REF(mmdst.m64, mmsrc.m64);
                    break;

                case 0x09:
                    //psignw64(&mmsrc,&mmdst,&mmres);
                    mmres.m64 = ssp_sign_pi16_REF(mmdst.m64, mmsrc.m64);
                    break;

                case 0x0A:
                    //psignd64(&mmsrc,&mmdst,&mmres);
                    mmres.m64 = ssp_sign_pi32_REF(mmdst.m64, mmsrc.m64);
                    break;

                case 0x0B:
                    //pmulhrsw64(&mmsrc,&mmdst,&mmres);
                    mmres.m64 = ssp_mulhrs_pi16_REF(mmdst.m64, mmsrc.m64);
                    break;

                case 0x0F:
                    //palignr64(&mmsrc,&mmdst,&mmres, (const int)operand);
                    mmres.m64 = ssp_alignr_pi8_REF(mmdst.m64, mmsrc.m64, palignr_getimm64(bytep));
                    ins_size++;
                    break;

                case 0x1C:
                    //pabsb64(&mmsrc,&mmres);
                    mmres.m64 = ssp_abs_pi8_REF(mmsrc.m64);
                    break;

                case 0x1D:
                    //pabsw64(&mmsrc,&mmres);
                    mmres.m64 = ssp_abs_pi16_REF(mmsrc.m64);
                    break;

                case 0x1E:
                    //pabsd64(&mmsrc,&mmres);
                    mmres.m64 = ssp_abs_pi32_REF(mmsrc.m64);
                    break;

                default:
                    return 0;
            }

            storeresult64(*modrm, dst_higher, mmres);
        }
        
    } else {
        // opcode wasn't handled here
        return 0;
    }
    
    return ins_size;
}

void print_bytes(uint8_t *from, int size)
{
    int i;
    for(i = 0; i < size; ++i)
    {
        printf("%02x ", from[i]);
    }
    printf("\n");
}

/** Fetch SSSE3 operands (except immediate values, which are fetched elsewhere).
 * We depend on memory copies, which differs depending on whether we're in kernel space
 * or not. For this reason, need to pass in a lot of information, including the state of
 * registers.
 *
 * The return value is the number of bytes used, including the ModRM byte,
 * and displacement values, as well as SIB if used.
 */
int fetchoperands(uint8_t *ModRM, unsigned int hsrc, unsigned int hdst, void *src, void *dst, unsigned int longmode, x86_saved_state_t *saved_state, int kernel_trap, int size_128, __unused int  ins_size)
{
    unsigned int num_src = *ModRM & 0x7;
    unsigned int num_dst = (*ModRM >> 3) & 0x7;
    unsigned int mod = *ModRM >> 6;
    int consumed = 1;
    
    if(hsrc) num_src += 8;
    if(hdst) num_dst += 8;
    if(size_128) getxmm((ssp_m128*)dst, num_dst);
    else getmm((ssp_m64*)dst, num_dst);
    
    if(mod == 3) {
        if(size_128) getxmm((ssp_m128*)src, num_src);
        else getmm((ssp_m64*)src, num_src);
    } else if ((longmode = is_saved_state64(saved_state))) {
        uint64_t address;
        
        // DST is always an XMM register. decode for SRC.
        x86_saved_state64_t *r64 = saved_state64(saved_state);
        __uint64_t reg_sel[8] = {r64->rax, r64->rcx, r64->rdx,
            r64->rbx, r64->isf.rsp, r64->rbp,
            r64->rsi, r64->rdi};
        if(hsrc) printf("opemu error: high reg ssse\n"); // FIXME
        if(num_src == 4) {
            // Special case: SIB byte used TODO fix r8-r15? 
            uint8_t scale = ModRM[1] >> 6;
            uint8_t base = ModRM[1] & 0x7;
            uint8_t index = (ModRM[1] >> 3) & 0x7;
            consumed++;
            
            // meaning of SIB depends on mod
            if(mod == 0) {
                if(base == 5) printf("opemu error: mod0 disp32 not implemented\n"); // FIXME
                if(index == 4) address = reg_sel[base];
                else
				address = reg_sel[base] + (reg_sel[index] * (1<<scale));
            } else {
                if(index == 4) 
				address = reg_sel[base];
                else 
				address = reg_sel[base] + (reg_sel[index] * (1<<scale));
            }
        } else {
            address = reg_sel[num_src];
        }
        
        if((mod == 0) && (num_src == 5)) {
            // RIP-relative dword displacement
            // AnV - Warning from cast alignment fix
            __uint64_t ModRMVal = (__uint64_t)&ModRM[consumed];
            __int32_t *ModRMCast = (__int32_t *)ModRMVal;
            address = *(uint32_t*)&r64->isf.rip + *ModRMCast;
            //printf("opemu adress rip: %llu \n",address);
            
            consumed += 4;
        }
		if(mod == 1) {
            // byte displacement
            address +=(int8_t)ModRM[consumed];
            //printf("opemu adress byte : %llu \n",address);
            consumed++;
        } else if(mod == 2) {
            // dword displacement. can it be qword?
            // AnV - Warning from cast alignment fix
            __uint64_t ModRMVal = (__uint64_t)&ModRM[consumed];
            __int32_t *ModRMCast = (__int32_t *)ModRMVal;
            address +=  *ModRMCast;
            
            //printf("opemu adress byte : %llu \n",address);
            consumed += 4;
        }
        
        // address is good now, do read and store operands.
        if(kernel_trap) {
            if(size_128) ((ssp_m128*)src)->ui = *(__uint128_t *)address;
            else ((ssp_m64*)src)->u64 = *(uint64_t *)address;
        } else {
            //printf("xnu: da = %llx, rsp=%llx,  rip=%llx\n", address, reg_sel[4], r64->isf.rip);
            if(size_128) copyin(address, (char*)& ((ssp_m128*)src)->u8, 16);
            else copyin(address, (char*)& ((ssp_m64*)src)->u8, 8);
        }
    }else {
        // AnV - Implemented 32-bit fetch
        uint32_t address;
        
        // DST is always an XMM register. decode for SRC.
        x86_saved_state32_t* r32 = saved_state32(saved_state);
        uint32_t reg_sel[8] = {r32->eax, r32->ecx, r32->edx,
            r32->ebx, r32->uesp, r32->ebp,
            r32->esi, r32->edi};
        if(hsrc) printf("opemu error: high reg ssse\n"); // FIXME
        if(num_src == 4) {
            /* Special case: SIB byte used TODO fix r8-r15? */
            uint8_t scale = ModRM[1] >> 6;
            uint8_t base = ModRM[1] & 0x7;
            uint8_t index = (ModRM[1] >> 3) & 0x7;
            consumed++;
            
            // meaning of SIB depends on mod
            if(mod == 0) {
                if(base == 5) printf("opemu error: mod0 disp32 not implemented\n"); // FIXME
                if(index == 4) address = reg_sel[base];
                else address = reg_sel[base] + (reg_sel[index] * (1<<scale));
            } else {
                if(index == 4) address = reg_sel[base];
                else address = reg_sel[base] + (reg_sel[index] * (1<<scale));
            }
        } else {
            address = reg_sel[num_src];
        }
        
        if((mod == 0) && (num_src == 5)) {
            // RIP-relative dword displacement
            // AnV - Warning from cast alignment fix
            uint64_t ModRMVal = (uint64_t)&ModRM[consumed];
            int32_t *ModRMCast = (int32_t *)ModRMVal;
            address = r32->eip + *ModRMCast;
            
            //address = r32->eip + *((int32_t*)&ModRM[consumed]);
            consumed += 4;
        } if(mod == 1) {
            // byte displacement
            //int32_t mods = (int32_t)ModRM[consumed];
            //int8_t *Mods = (int8_t*)&mods;
            address += (int8_t)ModRM[consumed];
            // printf("opemu adress byte : %llu \n",address);
            consumed++;
        } else if(mod == 2) {
            // dword displacement. can it be qword?
            // AnV - Warning from cast alignment fix
            uint64_t ModRMVal = (uint64_t)&ModRM[consumed];
            int32_t *ModRMCast = (int32_t *)ModRMVal;
            address += *ModRMCast;
            
            //address += *((int32_t*)&ModRM[consumed]);
            consumed += 4;
        }
        
        // address is good now, do read and store operands.
        uint64_t addr = address;
        
        if(kernel_trap) {
            if(size_128) ((ssp_m128*)src)->ui = *(__uint128_t *)addr;
            else ((ssp_m64*)src)->u64 = *(uint64_t *)addr;
        } else {
            //printf("xnu: da = %llx, rsp=%llx,  rip=%llx\n", address, reg_sel[4], r32->eip);
            if(size_128) copyin(addr, (char*) &((ssp_m128*)src)->u8, 16);
            else copyin(addr, (char*) &((ssp_m64*)src)->u64, 8);
        }
    }
    
    return consumed;
}

void storeresult128(uint8_t ModRM, unsigned int hdst, ssp_m128 res)
{
    unsigned int num_dst = (ModRM >> 3) & 0x7;
    if(hdst) num_dst += 8;
    movxmm(&res, num_dst);
}

void storeresult64(uint8_t ModRM, unsigned int __unused hdst, ssp_m64 res)
{
    unsigned int num_dst = (ModRM >> 3) & 0x7;
    movmm(&res, num_dst);
}

#endif /* TESTCASE */

/* get value from the xmm register i */
void getxmm(ssp_m128 *v, unsigned int i)
{
    switch(i) {
        case 0:
            asm __volatile__ ("movdqu %%xmm0, %0" : "=m" (v->u64));
            break;
        case 1:
            asm __volatile__ ("movdqu %%xmm1, %0" : "=m" (v->u64));
            break;
        case 2:
            asm __volatile__ ("movdqu %%xmm2, %0" : "=m" (v->u64));
            break;
        case 3:
            asm __volatile__ ("movdqu %%xmm3, %0" : "=m" (v->u64));
            break;
        case 4:
            asm __volatile__ ("movdqu %%xmm4, %0" : "=m" (v->u64));
            break;
        case 5:
            asm __volatile__ ("movdqu %%xmm5, %0" : "=m" (v->u64));
            break;
        case 6:
            asm __volatile__ ("movdqu %%xmm6, %0" : "=m" (v->u64));
            break;
        case 7:
            asm __volatile__ ("movdqu %%xmm7, %0" : "=m" (v->u64));
            break;
#ifdef __x86_64__
        case 8:
            asm __volatile__ ("movdqu %%xmm8, %0" : "=m" (v->u64));
            break;
        case 9:
            asm __volatile__ ("movdqu %%xmm9, %0" : "=m" (v->u64));
            break;
        case 10:
            asm __volatile__ ("movdqu %%xmm10, %0" : "=m" (v->u64));
            break;
        case 11:
            asm __volatile__ ("movdqu %%xmm11, %0" : "=m" (v->u64));
            break;
        case 12:
            asm __volatile__ ("movdqu %%xmm12, %0" : "=m" (v->u64));
            break;
        case 13:
            asm __volatile__ ("movdqu %%xmm13, %0" : "=m" (v->u64));
            break;
        case 14:
            asm __volatile__ ("movdqu %%xmm14, %0" : "=m" (v->u64));
            break;
        case 15:
            asm __volatile__ ("movdqu %%xmm15, %0" : "=m" (v->u64));
            break;
#endif
    }
}

/* get value from the mm register i  */
void getmm(ssp_m64 *v, unsigned int i)
{
    switch(i) {
        case 0:
            asm __volatile__ ("movq %%mm0, %0" : "=m" (v->u64));
            break;
        case 1:
            asm __volatile__ ("movq %%mm1, %0" : "=m" (v->u64));
            break;
        case 2:
            asm __volatile__ ("movq %%mm2, %0" : "=m" (v->u64));
            break;
        case 3:
            asm __volatile__ ("movq %%mm3, %0" : "=m" (v->u64));
            break;
        case 4:
            asm __volatile__ ("movq %%mm4, %0" : "=m" (v->u64));
            break;
        case 5:
            asm __volatile__ ("movq %%mm5, %0" : "=m" (v->u64));
            break;
        case 6:
            asm __volatile__ ("movq %%mm6, %0" : "=m" (v->u64));
            break;
        case 7:
            asm __volatile__ ("movq %%mm7, %0" : "=m" (v->u64));
            break;
    }
}

/* move value over to xmm register i */
void movxmm(ssp_m128 *v, unsigned int i)
{
    switch(i) {
        case 0:
            asm __volatile__ ("movdqu %0, %%xmm0" :: "m" (v->ui) );
            break;
        case 1:
            asm __volatile__ ("movdqu %0, %%xmm1" :: "m" (v->ui) );
            break;
        case 2:
            asm __volatile__ ("movdqu %0, %%xmm2" :: "m" (v->ui) );
            break;
        case 3:
            asm __volatile__ ("movdqu %0, %%xmm3" :: "m" (v->ui) );
            break;
        case 4:
            asm __volatile__ ("movdqu %0, %%xmm4" :: "m" (v->ui) );
            break;
        case 5:
            asm __volatile__ ("movdqu %0, %%xmm5" :: "m" (v->ui) );
            break;
        case 6:
            asm __volatile__ ("movdqu %0, %%xmm6" :: "m" (v->ui) );
            break;
        case 7:
            asm __volatile__ ("movdqu %0, %%xmm7" :: "m" (v->ui) );
            break;
#ifdef __x86_64__
        case 8:
            asm __volatile__ ("movdqu %0, %%xmm8" :: "m" (v->ui) );
            break;
        case 9:
            asm __volatile__ ("movdqu %0, %%xmm9" :: "m" (v->ui) );
            break;
        case 10:
            asm __volatile__ ("movdqu %0, %%xmm10" :: "m" (v->ui) );
            break;
        case 11:
            asm __volatile__ ("movdqu %0, %%xmm11" :: "m" (v->ui) );
            break;
        case 12:
            asm __volatile__ ("movdqu %0, %%xmm12" :: "m" (v->ui) );
            break;
        case 13:
            asm __volatile__ ("movdqu %0, %%xmm13" :: "m" (v->ui) );
            break;
        case 14:
            asm __volatile__ ("movdqu %0, %%xmm14" :: "m" (v->ui) );
            break;
        case 15:
            asm __volatile__ ("movdqu %0, %%xmm15" :: "m" (v->ui) );
            break;
#endif
    }
}

/* move value over to mm register i */
void movmm(ssp_m64 *v, unsigned int i)
{
    switch(i) {
        case 0:
            asm __volatile__ ("movq %0, %%mm0" :: "m" (v->u64) );
            break;
        case 1:
            asm __volatile__ ("movq %0, %%mm1" :: "m" (v->u64) );
            break;
        case 2:
            asm __volatile__ ("movq %0, %%mm2" :: "m" (v->u64) );
            break;
        case 3:
            asm __volatile__ ("movq %0, %%mm3" :: "m" (v->u64) );
            break;
        case 4:
            asm __volatile__ ("movq %0, %%mm4" :: "m" (v->u64) );
            break;
        case 5:
            asm __volatile__ ("movq %0, %%mm5" :: "m" (v->u64) );
            break;
        case 6:
            asm __volatile__ ("movq %0, %%mm6" :: "m" (v->u64) );
            break;
        case 7:
            asm __volatile__ ("movq %0, %%mm7" :: "m" (v->u64) );
            break;
    }
}

short fisttps(float *res)
{
    float value = opemu_truncf(*res);
    __asm__ ("fistps %0" : : "m" (value));
    *res = value;
    return (short)(res);
}

int fisttpl(double *res)
{
    double value = opemu_trunc(*res);
    __asm__ ("fistpl %0" : : "m" (value));
    *res = value;
    return (int)res;
}

long long fisttpq(long double *res)
{
    long double value = *res;
    __asm__ ("fistpq %0" : : "m" (value));
    *res = value;
    return (long long)res;
}
