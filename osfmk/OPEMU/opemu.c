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
#include <SSEPlus/SSEPlus_SSSE3.h>

#ifndef TESTCASE
#include <kern/sched_prim.h>

//#define EMULATION_FAILED -1

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
    int longmode;
    longmode = is_saved_state64(state);

    //Enable SSSE3 Soft Emulation
    bytes_skip = ssse3_run(code_buffer, state, longmode, 1);

    //Enable SSE3 Soft Emulation
    if (!bytes_skip)
    {
        bytes_skip = sse3_run(code_buffer, state, longmode, 1);
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
        uint8_t code0 = code_buffer[0];
        uint8_t code1 = code_buffer[1];
        uint8_t code2 = code_buffer[2];
        uint8_t code3 = code_buffer[3];
        uint8_t code4 = code_buffer[4];
        uint8_t code5 = code_buffer[5];
        uint8_t code6 = code_buffer[6];
        uint8_t code7 = code_buffer[7];
        uint8_t code8 = code_buffer[8];
        uint8_t code9 = code_buffer[9];

        printf("invalid kernel opcode (64-bit): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", code0, code1, code2, code3, code4, code5, code6, code7, code8, code9);
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
    int longmode;
    longmode = is_saved_state32(state);

    //Enable SSSE3 Soft Emulation
    bytes_skip = ssse3_run(code_buffer, state, longmode, 1);

    //Enable SSE3 Soft Emulation
    if (!bytes_skip)
    {
        bytes_skip = sse3_run(code_buffer, state, longmode, 1);
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
        uint8_t code0 = code_buffer[0];
        uint8_t code1 = code_buffer[1];
        uint8_t code2 = code_buffer[2];
        uint8_t code3 = code_buffer[3];
        uint8_t code4 = code_buffer[4];
        uint8_t code5 = code_buffer[5];
        uint8_t code6 = code_buffer[6];
        uint8_t code7 = code_buffer[7];
        uint8_t code8 = code_buffer[8];
        uint8_t code9 = code_buffer[9];

        printf("invalid kernel opcode (32-bit): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", code0, code1, code2, code3, code4, code5, code6, code7, code8, code9);
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

		//sysenter
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

		//sysexit
        if (opcode == 0x350f)
        {
            regs->isf.rip = regs->rdx;
            regs->isf.rsp = regs->rcx;
            thread_exception_return();
            /*if (kernel_trap)
            {
                addr = regs->rcx;
                return 0x7FFF;
            }
            else
            {
                thread_exception_return();
            }*/
            return;
        }

        //Enable SSSE3 Soft Emulation
        bytes_skip = ssse3_run(code_buffer, state, longmode, 0);

        //Enable SSE3 Soft Emulation
        if (!bytes_skip)
        {
            bytes_skip = sse3_run(code_buffer, state, longmode, 0);
        }

        regs->isf.rip += bytes_skip;

        if(!bytes_skip)
        {
            uint8_t code0 = code_buffer[0];
            uint8_t code1 = code_buffer[1];
            uint8_t code2 = code_buffer[2];
            uint8_t code3 = code_buffer[3];
            uint8_t code4 = code_buffer[4];
            uint8_t code5 = code_buffer[5];
            uint8_t code6 = code_buffer[6];
            uint8_t code7 = code_buffer[7];
            uint8_t code8 = code_buffer[8];
            uint8_t code9 = code_buffer[9];

            printf("invalid user opcode (64-bit): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", code0, code1, code2, code3, code4, code5, code6, code7, code8, code9);
            /* Fall through to trap */
            return;
        }
    }
    else
    {
        x86_saved_state32_t *saved_state = saved_state32(state);
        uint64_t op = saved_state->eip;
        uint8_t *code_buffer = (uint8_t*)op;
        addr = saved_state->eip;
        uint16_t opcode;
        opcode = *(uint16_t *) addr;
        x86_saved_state32_t *regs;
        regs = saved_state32(state);

        //sysenter
        if (opcode == 0x340f)
        {
            regs->eip = regs->edx;
            regs->uesp = regs->ecx;

            if((signed int)regs->eax < 0) {
                mach_call_munger(state);
            } else {
                unix_syscall(state);
            }
            return;
        }

        //sysexit
        if (opcode == 0x350f)
        {
            regs->eip = regs->edx;
            regs->uesp = regs->ecx;
            thread_exception_return();
            return;
        }

        //Enable SSSE3 Soft Emulation
        bytes_skip = ssse3_run(code_buffer, state, longmode, 0);

        //Enable SSE3 Soft Emulation
        if (!bytes_skip)
        {
            bytes_skip = sse3_run(code_buffer, state, longmode, 0);
        }

        regs->eip += bytes_skip;
        
        if(!bytes_skip)
        {
            uint8_t code0 = code_buffer[0];
            uint8_t code1 = code_buffer[1];
            uint8_t code2 = code_buffer[2];
            uint8_t code3 = code_buffer[3];
            uint8_t code4 = code_buffer[4];
            uint8_t code5 = code_buffer[5];
            uint8_t code6 = code_buffer[6];
            uint8_t code7 = code_buffer[7];
            uint8_t code8 = code_buffer[8];
            uint8_t code9 = code_buffer[9];

            printf("invalid user opcode (32-bit): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", code0, code1, code2, code3, code4, code5, code6, code7, code8, code9);
            /* Fall through to trap */
            return;
        }
    }
    thread_exception_return();
    /*** NOTREACHED ***/
    //EMULATION_FAILED;
}

/*
void print_bytes(uint8_t *from, int size)
{
    int i;
    for(i = 0; i < size; ++i)
    {
        printf("%02x ", from[i]);
    }
    printf("\n");
}
*/

/** Runs the sse3 emulator. returns the number of bytes consumed.
 **/
int sse3_run(uint8_t *instruction, x86_saved_state_t *state, int longmode, int kernel_trap)
{
    uint8_t *bytep = instruction;
    int ins_size = 0;
    ssp_m128 xmmsrc, xmmdst, xmmres;
    int src_higher = 0, dst_higher = 0;
    int modbyte = 0; //Calculate byte 0 - modrm long
    int fisttp = 0;
    int rex = 0; //REX Mode
    int hsreg = 0; //High Source Register Only

    // SSE3 Type 1
    if(*bytep == 0x66 && bytep[1] == 0x0f)
    {
        bytep += 2;
        ins_size += 2;
        modbyte += 4;

        uint8_t *modrm = &bytep[1];
        ins_size += 1;
        int consumed = operands(modrm, src_higher, dst_higher, &xmmsrc, &xmmdst, longmode, state, kernel_trap, 1, rex, hsreg, modbyte, fisttp);
        ins_size += consumed;

        switch (*bytep)
        {
            case 0x7C: //haddpd(&xmmsrc,&xmmdst,&xmmres); break;
                xmmres.d = ssp_hadd_pd_REF(xmmdst.d, xmmsrc.d); break;
            case 0x7D: //hsubpd(&xmmsrc,&xmmdst,&xmmres); break;
                xmmres.d = ssp_hsub_pd_REF(xmmdst.d, xmmsrc.d); break;
            case 0xD0: //addsubpd(&xmmsrc,&xmmdst,&xmmres); break;
                xmmres.d = ssp_addsub_pd_REF(xmmdst.d, xmmsrc.d); break;
            default: return 0;
        }

        storeresult128(*modrm, dst_higher, xmmres);

        return ins_size;
    }

    // SSE3 Type 2
    else if(*bytep == 0xF2 && bytep[1] == 0x0f)
    {
        bytep += 2;
        ins_size += 2;
        modbyte += 4;

        uint8_t *modrm = &bytep[1];
        ins_size += 1;
        int consumed = operands(modrm, src_higher, dst_higher, &xmmsrc, &xmmdst, longmode, state, kernel_trap, 1, rex, hsreg, modbyte, fisttp);
        ins_size += consumed;

        switch (*bytep)
        {
            case 0x12: //movddup(&xmmsrc,&xmmres); break;
                xmmres.d = ssp_movedup_pd_REF(xmmsrc.d); break;
            case 0x7C: //haddps(&xmmsrc,&xmmdst,&xmmres); break;
                xmmres.f = ssp_hadd_ps_REF(xmmdst.f, xmmsrc.f); break;
            case 0x7D: //hsubps(&xmmsrc,&xmmdst,&xmmres); break;
                xmmres.f = ssp_hsub_ps_REF(xmmdst.f, xmmsrc.f); break;
            case 0xD0: //addsubps(&xmmsrc,&xmmdst,&xmmres); break;
                xmmres.f = ssp_addsub_ps_REF(xmmdst.f, xmmsrc.f); break;
            case 0xF0: //lddqu(&xmmsrc,&xmmres); break;
                xmmres.i = ssp_lddqu_si128_REF(&xmmsrc.i); break;
            default: return 0;
        }

        storeresult128(*modrm, dst_higher, xmmres);

        return ins_size;
    }

    // SSE3 Type 3
    else if(*bytep == 0xF3 && bytep[1] == 0x0f)
    {
        bytep += 2;
        ins_size += 2;
        modbyte += 4;

        uint8_t *modrm = &bytep[1];
        ins_size += 1;
        int consumed = operands(modrm, src_higher, dst_higher, &xmmsrc, &xmmdst, longmode, state, kernel_trap, 1, rex, hsreg, modbyte, fisttp);
        ins_size += consumed;

        switch (*bytep)
        {
            case 0x12: //movsldup(&xmmsrc,&xmmres); break;
                xmmres.f = ssp_moveldup_ps_REF(xmmsrc.f); break;
            case 0x16: //movshdup(&xmmsrc,&xmmres); break;
                xmmres.f = ssp_movehdup_ps_REF(xmmsrc.f); break;
            default: return 0;
        }

        storeresult128(*modrm, dst_higher, xmmres);

        return ins_size;
    }

    //SSE3 FISTTP
    //else if ((*bytep == 0x66 && bytep[1] == 0xDB)||(*bytep == 0x66 && bytep[1] == 0xDD)||(*bytep == 0x66 && bytep[1] == 0xDF))
    else if ((*bytep == 0xDB)||(*bytep == 0xDD)||(*bytep == 0xDF))
    {
        //bytep++;
        //ins_size += 2;
        //modbyte += 3;

        ins_size++;
        modbyte += 2;

        switch (*bytep)
        {
            case 0xDB: //fild 0xDB
                fisttp = 1;
                break;
            case 0xDD: //fld 0xDD
                fisttp = 2;
                break;
            case 0xDF: //fild 0xDF
                fisttp = 3;
                break;
        }

        uint8_t *modrm = &bytep[1];
        int consumed = operands(modrm, src_higher, dst_higher, &xmmsrc, &xmmdst, longmode, state, kernel_trap, 1, rex, hsreg, modbyte, fisttp);
        ins_size += consumed;

        return ins_size;
    }

    //SSE3 monitor/mwait
    else if((*bytep == 0x0F) && (bytep[1] == 0x01))
    {

        bytep += 2;
        ins_size += 3;

        switch(*bytep)
        {
            
            case 0xC8: break; //monitor: 0x0f,0x01,0xc8
            case 0xC9: break; //mwait: 0x0f,0x01,0xc9
            default: return 0;
        }

        return ins_size;
    }

    return ins_size;
}

/** Runs the ssse3 emulator. returns the number of bytes consumed.
 **/
int ssse3_run(uint8_t *instruction, x86_saved_state_t *state, int longmode, int kernel_trap)
{
    // pointer to the current byte we're working on
    uint8_t *bytep = instruction;
    int ins_size = 0;
    int is_128 = 0, src_higher = 0, dst_higher = 0;
    int modbyte = 0; //Calculate byte 0 - modrm long
    int fisttp = 0;
    int rex = 0; //REX Mode
    int hsreg = 0; //High Source Register Only

    ssp_m128 xmmsrc, xmmdst, xmmres;
    ssp_m64 mmsrc,mmdst, mmres;

    /* We can get a few prefixes, in any order:
     * 66 throws into 128-bit xmm mode.
     */
    if(*bytep == 0x66)
    {
        is_128 = 1;
        bytep++;
        ins_size++;
        modbyte++;
    }

    /* REX Prefixes 40-4F Use REX Mode.
     * Use higher registers.
     * xmm8-15 or R8-R15.
     */
    if((*bytep & 0xF0) == 0x40)
    {
        rex = 1;
        if(*bytep & 1) src_higher = 1;
        if(*bytep & 4) dst_higher = 1;

        /*** High Source Register Only ***/
        if((*bytep == 0x41)||(*bytep == 0x43)||(*bytep == 0x49)||(*bytep == 0x4B))
            hsreg = 1;

        bytep++;
        ins_size++;
        modbyte++;
    }

    if(*bytep != 0x0f) return 0;

    bytep++;
    ins_size++;
    modbyte++;

    /* Two SSSE3 instruction prefixes. */
    if(((*bytep == 0x38) && (bytep[1] != 0x0f)) || ((*bytep == 0x3a) && (bytep[1] == 0x0f)))
    {
        uint8_t opcode = bytep[1];
        uint8_t *modrm = &bytep[2];
        uint8_t imm;
/*
        uint8_t mod = *modrm >> 6;
        uint8_t num_src = *modrm & 0x7;
        uint8_t *sib = &bytep[3];
        uint8_t base = *sib & 0x7;

        if (mod == 0)
        {
            if (num_src == 4)
                if(base == 5) imm = *((uint8_t*)&bytep[8]); //modrm offset + 6
                else imm = *((uint8_t*)&bytep[4]); //modrm offset + 2
            else if (num_src == 5) imm = *((uint8_t*)&bytep[7]); //modrm offset + 5
            else imm = *((uint8_t*)&bytep[3]); //modrm offset + 1
        }

        if (mod == 1)
        {
            if(num_src == 4) imm = *((uint8_t*)&bytep[5]); //modrm offset + 3
            else imm = *((uint8_t*)&bytep[4]); //modrm offset + 2
        }

        if (mod == 2)
        {
            if(num_src == 4) imm = *((uint8_t*)&bytep[8]); //modrm offset + 6
            else imm = *((uint8_t*)&bytep[7]); //modrm offset + 5
        }

        if (mod == 3) imm = *((uint8_t*)&bytep[3]); //modrm offset + 1
*/
        ins_size += 2; // not counting modRM byte or anything after.
        if((*bytep == 0x3a) && (bytep[1] == 0x0f)) modbyte += 4;
        else modbyte += 3;

        if(is_128)
        {
            int consumed = operands(modrm, src_higher, dst_higher, &xmmsrc, &xmmdst, longmode, state, kernel_trap, 1, rex, hsreg, modbyte, fisttp);
            imm = *((uint8_t*)&bytep[2 + consumed]);
            ins_size += consumed;

            switch(opcode)
            {
                case 0x00: //pshufb128(&xmmsrc,&xmmdst,&xmmres); break;
                    xmmres.i = ssp_shuffle_epi8_SSSE3 (xmmdst.i, xmmsrc.i); break;
                case 0x01: //phaddw128(&xmmsrc,&xmmdst,&xmmres); break;
                    xmmres.i = ssp_hadd_epi16_SSSE3 (xmmdst.i, xmmsrc.i); break;
                case 0x02: //phaddd128(&xmmsrc,&xmmdst,&xmmres); break;
                    xmmres.i = ssp_hadd_epi32_SSSE3 (xmmdst.i, xmmsrc.i); break;
                case 0x03: //phaddsw128(&xmmsrc,&xmmdst,&xmmres); break;
                    xmmres.i = ssp_hadds_epi16_SSSE3 (xmmdst.i, xmmsrc.i); break;
                case 0x04: //pmaddubsw128(&xmmsrc,&xmmdst,&xmmres); break;
                    xmmres.i = ssp_maddubs_epi16_SSSE3 (xmmdst.i, xmmsrc.i); break;
                case 0x05: //phsubw128(&xmmsrc,&xmmdst,&xmmres); break;
                    xmmres.i = ssp_hsub_epi16_SSSE3 (xmmdst.i, xmmsrc.i); break;
                case 0x06: //phsubd128(&xmmsrc,&xmmdst,&xmmres); break;
                    xmmres.i = ssp_hsub_epi32_SSSE3 (xmmdst.i, xmmsrc.i); break;
                case 0x07: //phsubsw128(&xmmsrc,&xmmdst,&xmmres); break;
                    xmmres.i = ssp_hsubs_epi16_SSSE3 (xmmdst.i, xmmsrc.i); break;
                case 0x08: //psignb128(&xmmsrc,&xmmdst,&xmmres); break;
                    xmmres.i = ssp_sign_epi8_SSSE3 (xmmdst.i, xmmsrc.i); break;
                case 0x09: //psignw128(&xmmsrc,&xmmdst,&xmmres); break;
                    xmmres.i = ssp_sign_epi16_SSSE3 (xmmdst.i, xmmsrc.i); break;
                case 0x0A: //psignd128(&xmmsrc,&xmmdst,&xmmres); break;
                    xmmres.i = ssp_sign_epi32_SSSE3 (xmmdst.i, xmmsrc.i); break;
                case 0x0B: //pmulhrsw128(&xmmsrc,&xmmdst,&xmmres); break;
                    xmmres.i = ssp_mulhrs_epi16_SSSE3 (xmmdst.i, xmmsrc.i); break;
                case 0x0F: //palignr128(&xmmsrc,&xmmdst,&xmmres,imm); ins_size++; break;
                    xmmres.i = ssp_alignr_epi8_SSSE3 (xmmdst.i, xmmsrc.i, imm); ins_size++; break;
                case 0x1C: //pabsb128(&xmmsrc,&xmmres); break;
                    xmmres.i = ssp_abs_epi8_SSSE3 (xmmsrc.i); break;
                case 0x1D: //pabsw128(&xmmsrc,&xmmres); break;
                    xmmres.i = ssp_abs_epi16_SSSE3 (xmmsrc.i); break;
                case 0x1E: //pabsd128(&xmmsrc,&xmmres); break;
                    xmmres.i = ssp_abs_epi32_SSSE3 (xmmsrc.i); break;
                default: return 0;
            }

            storeresult128(*modrm, dst_higher, xmmres);
        }
        else
        {
            int consumed = operands(modrm, src_higher, dst_higher, &mmsrc, &mmdst, longmode, state, kernel_trap, 0, rex, hsreg, modbyte, fisttp);
            imm = *((uint8_t*)&bytep[2 + consumed]);
            ins_size += consumed;

            switch(opcode)
            {
                case 0x00: //pshufb64(&mmsrc,&mmdst,&mmres); break;
                    mmres.m64 = ssp_shuffle_pi8_SSSE3 (mmdst.m64, mmsrc.m64); break;
                case 0x01: //phaddw64(&mmsrc,&mmdst,&mmres); break;
                    mmres.m64 = ssp_hadd_pi16_SSSE3 (mmdst.m64, mmsrc.m64); break;
                case 0x02: //phaddd64(&mmsrc,&mmdst,&mmres); break;
                    mmres.m64 = ssp_hadd_pi32_SSSE3 (mmdst.m64, mmsrc.m64); break;
                case 0x03: //phaddsw64(&mmsrc,&mmdst,&mmres); break;
                    mmres.m64 = ssp_hadds_pi16_SSSE3 (mmdst.m64, mmsrc.m64); break;
                case 0x04: //pmaddubsw64(&mmsrc,&mmdst,&mmres); break;
                    mmres.m64 = ssp_maddubs_pi16_SSSE3 (mmdst.m64, mmsrc.m64); break;
                case 0x05: //phsubw64(&mmsrc,&mmdst,&mmres); break;
                    mmres.m64 = ssp_hsub_pi16_SSSE3 (mmdst.m64, mmsrc.m64); break;
                case 0x06: //phsubd64(&mmsrc,&mmdst,&mmres); break;
                    mmres.m64 = ssp_hsub_pi32_SSSE3 (mmdst.m64, mmsrc.m64); break;
                case 0x07: //phsubsw64(&mmsrc,&mmdst,&mmres); break;
                    mmres.m64 = ssp_hsubs_pi16_SSSE3 (mmdst.m64, mmsrc.m64); break;
                case 0x08: //psignb64(&mmsrc,&mmdst,&mmres); break;
                    mmres.m64 = ssp_sign_pi8_SSSE3 (mmdst.m64, mmsrc.m64); break;
                case 0x09: //psignw64(&mmsrc,&mmdst,&mmres); break;
                    mmres.m64 = ssp_sign_pi16_SSSE3 (mmdst.m64, mmsrc.m64); break;
                case 0x0A: //psignd64(&mmsrc,&mmdst,&mmres); break;
                    mmres.m64 = ssp_sign_pi32_SSSE3 (mmdst.m64, mmsrc.m64); break;
                case 0x0B: //pmulhrsw64(&mmsrc,&mmdst,&mmres); break;
                    mmres.m64 = ssp_mulhrs_pi16_SSSE3 (mmdst.m64, mmsrc.m64); break;
                case 0x0F: //palignr64(&mmsrc,&mmdst,&mmres, imm); ins_size++; break;
                    mmres.m64 = ssp_alignr_pi8_SSSE3 (mmdst.m64, mmsrc.m64, imm); ins_size++; break;
                case 0x1C: //pabsb64(&mmsrc,&mmres); break;
                    mmres.m64 = ssp_abs_pi8_SSSE3 (mmsrc.m64); break;
                case 0x1D: //pabsw64(&mmsrc,&mmres); break;
                    mmres.m64 = ssp_abs_pi16_SSSE3 (mmsrc.m64); break;
                case 0x1E: //pabsd64(&mmsrc,&mmres); break;
                    mmres.m64 = ssp_abs_pi32_SSSE3 (mmsrc.m64); break;
                default: return 0;
            }

            storeresult64(*modrm, dst_higher, mmres);
        }
    }
    else
    {
        // opcode wasn't handled here
        return 0;
    }

    return ins_size;
}

/* Fetch SSEX operands (except immediate values, which are fetched elsewhere).
 * We depend on memory copies, which differs depending on whether we're in kernel space
 * or not. For this reason, need to pass in a lot of information, including the state of
 * registers.
 *
 * The return value is the number of bytes used, including the ModRM byte,
 * and displacement values, as well as SIB if used.
 */
int operands(uint8_t *ModRM, unsigned int hsrc, unsigned int hdst, void *src, void *dst, unsigned int longmode, x86_saved_state_t *saved_state, int kernel_trap, int size_128, int rex, int hsreg, int modbyte, int fisttp)
{
    /*** ModRM Is First Addressing Modes ***/
    /*** SIB Is Second Addressing Modes ***/
    unsigned int num_src = *ModRM & 0x7; // R/M (register or memory) 
    unsigned int num_dst = (*ModRM >> 3) & 0x7; // digit/xmm register (xmm/mm)
    unsigned int mod = *ModRM >> 6; // Mod
    int consumed = 1; //modrm + 1 byte
    uint8_t bytelong = 0x00;

    if(hsrc) num_src += 8;
    if(hdst) num_dst += 8;

    if(size_128) getxmm((ssp_m128*)dst, num_dst);
    else getmm((ssp_m64*)dst, num_dst);

    if(mod == 3) //mod field = 11b
    {
        if(size_128) getxmm((ssp_m128*)src, num_src);
        else getmm((ssp_m64*)src, num_src);
    }

    // Implemented 64-bit fetch
    else if ((longmode = is_saved_state64(saved_state)))
    {
        uint64_t address;
        // DST is always an XMM register. decode for SRC.
        uint64_t reg_sel[8];
        x86_saved_state64_t *r64 = saved_state64(saved_state);

        if (hsrc)
        {
            reg_sel[0] = r64->r8;
            reg_sel[1] = r64->r9;
            reg_sel[2] = r64->r10;
            reg_sel[3] = r64->r11;
            reg_sel[4] = r64->r12;
            reg_sel[5] = r64->r13;
            reg_sel[6] = r64->r14;
            reg_sel[7] = r64->r15;
        }
        else
        {
            reg_sel[0] = r64->rax;
            reg_sel[1] = r64->rcx;
            reg_sel[2] = r64->rdx;
            reg_sel[3] = r64->rbx;
            reg_sel[4] = r64->isf.rsp;
            reg_sel[5] = r64->rbp;
            reg_sel[6] = r64->rsi;
            reg_sel[7] = r64->rdi;
        }

        /*** DEBUG ***/
        //if(hdst) printf("opemu debug: high Register ssse\n"); // use xmm8-xmm15 register

        /*** REX Prefixes 40-4F Use REX Mode ***/
        if (rex)
        {
            /*** R/M = RSP/R12 USE SIB Addressing Modes ***/
            if (num_src == 4)
            {
                uint8_t *sib = (uint8_t *)&ModRM[1]; //Second Addressing Modes
                uint8_t scale = *sib >> 6; //SIB Scale field
                uint8_t base = *sib & 0x7; //SIB Base
                uint8_t index = (*sib >> 3) & 0x7; //SIB Index
                uint8_t factor; //Scaling factor
                if (scale == 0) factor = 1;
                else if (scale == 1) factor = 2;
                else if (scale == 2) factor = 4;
                else if (scale == 3) factor = 8;

                if (mod == 0) //mod field = 00b
                {
                    if(base == 5) //Base Register = RBP
                    {
                        if(index == 4) //Base Register = RBP & Index Register = RSP
                        {
                            if (hsreg)
                            {
                                //ModRM                 0  1  2  3  4  5
                                //byte   0  1  2  3  4  5  6  7  8  9  10
                                //OPCPDE 66 43 0F 38 01 04 65 04 03 02 01
                                //INS    phaddw xmm0, xmmword [ds:0x1020304+r12*2]
                                //PTR = Disp32 + (Index*Scale)
                                bytelong = modbyte + 5;
                                address = (r64->isf.rip + bytelong + *((int32_t*)&ModRM[2])) + (reg_sel[index] * factor);
                                consumed += 5;
                            }
                            else
                            {
                                //ModRM                 0  1  2  3  4  5
                                //byte   0  1  2  3  4  5  6  7  8  9  10
                                //OPCPDE 66 40 0F 38 01 04 65 04 03 02 01
                                //INS    phaddw xmm0, xmmword [ds:0x1020304]
                                //PTR = Disp32
                                bytelong = modbyte + 5;
                                address = r64->isf.rip + bytelong + *((int32_t*)&ModRM[2]);
                                consumed += 5;
                            }
                        }
                        else //base 5 & Not Index 4
                        {
                            //ModRM                 0  1  2  3  4  5
                            //byte   0  1  2  3  4  5  6  7  8  9  10
                            //OPCPDE 66 43 0F 38 01 04 45 04 03 02 01
                            //INS    phaddw xmm0, xmmword [ds:0x1020304+r8*2]
                            //PTR = Disp32 + (Index*Scale)
                            bytelong = modbyte + 5;
                            address = (r64->isf.rip + bytelong + *((int32_t*)&ModRM[2])) + (reg_sel[index] * factor);
                            consumed += 5;
                        }
                    }
                    else //Not Base 5
                    {
                        if (index == 4) // Index Register = RSP
                        {
                            if (hsreg)
                            {
                                //ModRM                 0  1
                                //byte   0  1  2  3  4  5  6
                                //OPCPDE 66 43 0F 38 01 04 64
                                //INS    phaddw xmm0, xmmword [ds:r12+r12*2]
                                //PTR = Base + (Index*Scale)
                                address = reg_sel[base] + (reg_sel[index] * factor);
                                consumed++;
                            }
                            else
                            {
                                //ModRM                 0  1
                                //byte   0  1  2  3  4  5  6
                                //OPCPDE 66 40 0F 38 01 04 63
                                //INS    phaddw xmm0, xmmword [ds:rbx]
                                //PTR = Base
                                address = reg_sel[base];
                                consumed++;
                            }
                        }
                        else //SIB General Mode
                        {
                            //ModRM                 0  1
                            //byte   0  1  2  3  4  5  6
                            //OPCPDE 66 43 0F 38 01 04 44
                            //INS    phaddw xmm0, xmmword [ds:r12+r8*2]
                            //PTR = Base + (Index*Scale)
                            address = reg_sel[base] + (reg_sel[index] * factor);
                            consumed++;
                        }
                    }
                }

                else if (mod == 1) //mod field = 01b
                {
                    if (index == 4) // Index Register = RSP
                    {
                        if (hsreg)
                        {
                            //ModRM                 0  1  2
                            //byte   0  1  2  3  4  5  6  7
                            //OPCPDE 66 43 0F 38 01 44 65 04
                            //INS    phaddw     xmm0, xmmword [ds:r13+r12*2+0x4]
                            //PTR = Base + (Index*Scale) + Disp8
                            address = reg_sel[base] + (reg_sel[index] * factor) + *((int8_t*)&ModRM[2]);
                            consumed+= 2;
                        }
                        else
                        {
                            //ModRM                 0  1  2
                            //byte   0  1  2  3  4  5  6  7
                            //OPCPDE 66 40 0F 38 01 44 65 04
                            //INS    phaddw xmm0, xmmword [ss:rbp+0x4]
                            //PTR = Base + Disp8
                            address = reg_sel[base] + *((int8_t*)&ModRM[2]);
                            consumed+= 2;
                        }
                    }
                    else //SIB General Mode
                    {
                        //ModRM                 0  1  2
                        //byte   0  1  2  3  4  5  6  7
                        //OPCPDE 66 40 0F 38 01 44 44 04
                        //INS    phaddw xmm0, xmmword [ss:rsp+rax*2+0x4]
                        //PTR = Base + (Index*Scale) + Disp32
                        address = reg_sel[base] + (reg_sel[index] * factor) + *((int8_t*)&ModRM[2]);
                        consumed+= 2;
                    }
                }

                else if (mod == 2) //mod field = 10b
                {
                    if (index == 4) // Index Register = RSP
                    {
                        if (hsreg)
                        {
                            //ModRM                 0  1  2  3  4  5
                            //byte   0  1  2  3  4  5  6  7  8  9  10
                            //OPCPDE 66 43 0F 38 01 84 64 04 03 02 01
                            //INS    phaddw xmm0, xmmword [ds:r12+r12*2+0x1020304]
                            //PTR = Base + (Index*Scale) + Disp32
                            bytelong = modbyte + 5;
                            address = reg_sel[base] + (reg_sel[index] * factor) + (r64->isf.rip + bytelong + *((int32_t*)&ModRM[2]));
                            consumed += 5;
                        }
                        else
                        {
                            //ModRM                 0  1  2  3  4  5
                            //byte   0  1  2  3  4  5  6  7  8  9  10
                            //OPCPDE 66 40 0F 38 01 84 64 04 03 02 01
                            //INS    phaddw xmm0, xmmword [ss:rsp+0x1020304]
                            //PTR = Base + Disp32
                            bytelong = modbyte + 5;
                            address = reg_sel[base] + (r64->isf.rip + bytelong + *((int32_t*)&ModRM[2]));
                            consumed += 5;
                        }
                    }
                    else //SIB General Mode
                    {
                        //ModRM                 0  1  2  3  4  5
                        //byte   0  1  2  3  4  5  6  7  8  9  10
                        //OPCPDE 66 43 0F 38 01 84 44 04 03 02 01
                        //INS    phaddw xmm0, xmmword [ds:r12+r8*2+0x1020304]
                        //PTR = Base + (Index*Scale) + Disp32
                        bytelong = modbyte + 5;
                        address = reg_sel[base] + (reg_sel[index] * factor) + (r64->isf.rip + bytelong + *((int32_t*)&ModRM[2]));
                        consumed += 5;
                    }
                }
            }
            /*** R/M = RBP in mod 0 Use Disp32 Offset ***/
            else if (num_src == 5)
            {
                if (mod == 0)
                {
                    //ModRM                 0  1  2  3  4
                    //byte   0  1  2  3  4  5  6  7  8  9
                    //OPCPDE 66 43 0F 38 01 05 04 03 02 01
                    //INS    phaddw xmm0, xmmword [ds:0x102112e]
                    //PTR = Disp32
                    bytelong = modbyte + 4;
                    address = r64->isf.rip + bytelong + *((int32_t*)&ModRM[1]);
                    consumed += 4;
                }
            }

            /*** General Mode ***/
            else
            {
                if (mod == 0) //mod field = 00b
                {
                    //ModRM                 0
                    //BYTE   0  1  2  3  4  5
                    //OPCPDE 66 43 0F 38 01 03
                    //INS    phaddw xmm0, xmmword [ds:r11]
                    //PTR = R/M
                    address = reg_sel[num_src];
                }
                else if (mod == 1) //mod field = 01b
                {
                    //ModRM                 0  1
                    //byte   0  1  2  3  4  5  6
                    //OPCPDE 66 43 0F 38 01 43 01
                    //INS    phaddw xmm0, xmmword [ds:r11+0x1]
                    //PTR = R/M + Disp8
                    address = reg_sel[num_src] + *((int8_t*)&ModRM[1]);
                    consumed++;
                }
                else if (mod == 2) //mod field = 10b
                {
                    //ModRM                 0  1  2  3  4
                    //byte   0  1  2  3  4  5  6  7  8  9
                    //OPCPDE 66 43 0F 38 01 83 04 03 02 01
                    //INS    phaddw xmm0, xmmword [ds:r11+0x1020304]
                    //PTR = R/M + Disp32
                    bytelong = modbyte + 4;
                    address = reg_sel[num_src] + (r64->isf.rip + bytelong + *((int32_t*)&ModRM[1]));
                    consumed += 4;
                }
            }

        } //REX Mode END
        else
        {
            /*** R/M = RSP USE SIB Addressing Modes ***/
            if (num_src == 4)
            {
                uint8_t *sib = (uint8_t *)&ModRM[1]; //Second Addressing Modes
                uint8_t scale = *sib >> 6; //SIB Scale field
                uint8_t base = *sib & 0x7; //SIB Base
                uint8_t index = (*sib >> 3) & 0x7; //SIB Index
                uint8_t factor; //Scaling factor
                if (scale == 0) factor = 1;
                else if (scale == 1) factor = 2;
                else if (scale == 2) factor = 4;
                else if (scale == 3) factor = 8;

                if (mod == 0) //mod field = 00b
                {
                    if(base == 5) //Base Register = RBP
                    {
                        if(index == 4) //Base Register = RBP & Index Register = RSP
                        {
                            //ModRM              0  1  2  3  4  5
                            //byte   0  1  2  3  4  5  6  7  8  9
                            //OPCPDE 66 0F 38 01 04 25 04 03 02 01
                            //INS    phaddw xmm0, xmmword [ds:0x1020304]
                            //PTR = Disp32
                            bytelong = modbyte + 5;
                            address = r64->isf.rip + bytelong + *((int32_t*)&ModRM[2]);
                            consumed += 5;
                        }
                        else //base 5 & Not Index 4
                        {
                            //ModRM              0  1  2  3  4  5
                            //byte   0  1  2  3  4  5  6  7  8  9
                            //OPCPDE 66 0F 38 01 04 05 04 03 02 01
                            //INS    phaddw xmm0, xmmword [ds:0x1020304+rax]
                            //PTR = Disp32 + (Index*Scale)
                            bytelong = modbyte + 5;
                            address = (r64->isf.rip + bytelong + *((int32_t*)&ModRM[2])) + (reg_sel[index] * factor);
                            consumed += 5;
                        }
                    }
                    else //Not Base 5
                    {
                        if (index == 4) // Index Register = RSP
                        {
                            //ModRM              0  1
                            //byte   0  1  2  3  4  5
                            //OPCPDE 66 0F 38 01 04 61
                            //INS    phaddw xmm0, xmmword [ds:rcx]
                            //PTR = Base
                            address = reg_sel[base];
                            consumed++;
                        }
                        else //SIB General Mode
                        {
                            //ModRM              0  1
                            //byte   0  1  2  3  4  5
                            //OPCPDE 66 0F 38 01 04 44
                            //INS    phaddw xmm0, xmmword ptr [rsp+rax*2]
                            //PTR = Base + (Index*Scale)
                            address = reg_sel[base] + (reg_sel[index] * factor);
                            consumed++;
                        }
                    }
                }

                else if (mod == 1) //mod field = 01b
                {
                    if (index == 4) // Index Register = RSP
                    {
                        //ModRM              0  1  2
                        //BYTE   0  1  2  3  4  5  6
                        //OPCPDE 66 0F 38 01 44 27 80
                        //INS    phaddw xmm0, xmmword ptr [rdi-80h]
                        //PTR = Base + Disp8
                        address = reg_sel[base] + *((int8_t*)&ModRM[2]);
                        consumed+= 2;
                    }
                    else //SIB General Mode
                    {
                        //ModRM              0  1  2
                        //BYTE   0  1  2  3  4  5  6
                        //OPCPDE 66 0F 38 01 44 44 80
                        //INS    phaddw xmm0, xmmword ptr [rsp+rax*2-80h]
                        //PTR = Base + (Index*Scale) + Disp8
                        address = reg_sel[base] + (reg_sel[index] * factor) + *((int8_t*)&ModRM[2]);
                        consumed+= 2;
                    }
                }

                else if (mod == 2) //mod field = 10b
                {
                    if (index == 4) // Index Register = RSP
                    {
                        //ModRM              0  1  2  3  4  5
                        //BYTE   0  1  2  3  4  5  6  7  8  9
                        //OPCPDE 66 0F 38 01 84 20 04 03 02 01
                        //INS    phaddw xmm0, xmmword ptr [rax+1020304h]
                        //PTR = Base + Disp32
                        bytelong = modbyte + 5;
                        address = reg_sel[base] + (r64->isf.rip + bytelong + *((int32_t*)&ModRM[2]));
                        consumed += 5;
                    }
                    else //SIB General Mode
                    {
                        //ModRM              0  1  2  3  4  5
                        //BYTE   0  1  2  3  4  5  6  7  8  9
                        //OPCPDE 66 0F 38 01 84 44 04 03 02 01
                        //INS    phaddw xmm0, xmmword ptr [rsp+rax*2+1020304h]
                        //PTR = Base + (Index*Scale) + Disp32
                        bytelong = modbyte + 5;
                        address = reg_sel[base] + (reg_sel[index] * factor) + (r64->isf.rip + bytelong + *((int32_t*)&ModRM[2]));
                        consumed += 5;
                    }
                }
            }
            /*** R/M = RBP in mod 0 Use Disp32 Offset ***/
            else if (num_src == 5)
            {
                if (mod == 0) //mod field = 00b
                {
                    //ModRM              0  1  2  3  4
                    //BYTE   0  1  2  3  4  5  6  7  8
                    //OPCPDE 66 0F 38 01 05 01 02 03 04
                    //INS    phaddw xmm0, xmmword ptr [cs:04030201h]
                    //PTR = Disp32
                    bytelong = modbyte + 4;
                    address = r64->isf.rip + bytelong + *((int32_t*)&ModRM[1]);
                    consumed += 4;
                    /***DEBUG***/
                    //int32_t ds = *((int32_t*)&ModRM[1]);
                    //printf("DEBUG-MSG: byte=%x, RIP=%llx ,DS=%d, PTR = %llx\n", bytelong , r64->isf.rip, ds, address);
                    /***DEBUG***/
                }
            }

            /*** General Mode ***/
            else
            {
                if (mod == 0) //mod field = 00b
                {
                    //ModRM              0
                    //BYTE   0  1  2  3  4
                    //OPCPDE 66 0F 38 01 03
                    //INS    phaddw xmm0, xmmword [ds:rbx]
                    //PTR = R/M
                    address = reg_sel[num_src];
                }
                else if (mod == 1) //mod field = 01b
                {
                    //ModRM              0  1
                    //BYTE   0  1  2  3  4  5
                    //OPCPDE 66 0F 38 01 43 01
                    //INS    phaddw xmm0, xmmword [ds:rbx+0x1]
                    //PTR = R/M + Disp8
                    address = reg_sel[num_src] + *((int8_t*)&ModRM[1]);
                    consumed++;
                }
                else if (mod == 2) //mod field = 10b
                {
                    //ModRM              0  1  2  3  4
                    //BYTE   0  1  2  3  4  5  6  7  8
                    //OPCPDE 66 0F 38 01 83 01 02 03 04
                    //INS    phaddw xmm0, xmmword [ds:rbx+0x4030201]
                    //PTR = R/M + Disp32
                    bytelong = modbyte + 4;
                    address = reg_sel[num_src] + (r64->isf.rip + bytelong + *((int32_t*)&ModRM[1]));
                    consumed += 4;
                }
            }
        }

        if (fisttp == 1) //fild 0x66 0xDB
        {
            *(int *)address = fisttpl((double *)address);
        }
        else if (fisttp == 2) //fld 0x66 0xDD
        {
            *(long long *)address = fisttpq((long double *)address);
        }
        else if (fisttp == 3) //fild 0x66 0xDF
        {
            *(short *)address = fisttps((float *)address);
        }
        else //fisttp = 0
        {
            // address is good now, do read and store operands.
            if(kernel_trap)
            {
                if(size_128) ((ssp_m128*)src)->ui = *((__uint128_t*)address);
                else ((ssp_m64*)src)->u64 = *((uint64_t*)address);
            }
            else
            {
                //printf("XNU: PTR = %llx, RIP=%llx, RSP=%llx\n", address, r64->isf.rip, reg_sel[4]);
                if(size_128) copyin(address, (char*)& ((ssp_m128*)src)->ui, 16);
                else copyin(address, (char*)& ((ssp_m64*)src)->u64, 8);
            }
        }
    }
    // AnV - Implemented 32-bit fetch
    else
    {
        uint32_t address;
        // DST is always an XMM register. decode for SRC.
        uint32_t reg_sel[8];
        x86_saved_state32_t* r32 = saved_state32(saved_state);

        reg_sel[0] = r32->eax;
        reg_sel[1] = r32->ecx;
        reg_sel[2] = r32->edx;
        reg_sel[3] = r32->ebx;
        reg_sel[4] = r32->uesp;
        reg_sel[5] = r32->ebp;
        reg_sel[6] = r32->esi;
        reg_sel[7] = r32->edi;

        if (hsrc) printf("opemu error: high r/m Reg ssse\n"); // FIXME

        /*** R/M = ESP USE SIB Addressing Modes ***/
        if (num_src == 4)
        {
            uint8_t *sib = (uint8_t *)&ModRM[1]; //Second Addressing Modes
            uint8_t scale = *sib >> 6; //SIB Scale field
            uint8_t base = *sib & 0x7; //SIB Base
            uint8_t index = (*sib >> 3) & 0x7; //SIB Index
            uint8_t factor; //Scaling factor
            if (scale == 0) factor = 1;
            else if (scale == 1) factor = 2;
            else if (scale == 2) factor = 4;
            else if (scale == 3) factor = 8;

            if (mod == 0) //mod field = 00b
            {
                if(base == 5) // Base Register = EBP
                {
                    if(index == 4) // Index Register = ESP & Base Register = EBP
                    {
                        //ModRM           0  1  2  3  4  5
                        //byte   0  1  2  3  4  5  6  7  8
                        //OPCPDE 0F 38 01 04 25 04 03 02 01
                        //INS    phaddw mm0, qword [ds:0x1020304]
                        //PTR = DISP32 OFFSET
                        address = *((uint32_t*)&ModRM[2]);
                        consumed += 5;
                    }
                    else //base 5 & Not Index 4 
                    {
                        //ModRM           0  1  2  3  4  5
                        //byte   0  1  2  3  4  5  6  7  8
                        //OPCPDE 0F 38 01 04 05 04 03 02 01
                        //INS    phaddw mm0, qword [ds:0x1020304+rax]
                        //PTR = (DISP32 OFFSET) + (INDEX REG * SCALE)
                        address = *((uint32_t*)&ModRM[2]) + (reg_sel[index] * factor);
                        consumed += 5;
                    }
                }
                else //Not Base 5
                {
                    if (index == 4) // Index Register = ESP
                    {
                        //ModRM           0  1
                        //byte   0  1  2  3  4
                        //OPCPDE 0F 38 01 04 61
                        //INS    phaddw mm0, qword [ds:rcx]
                        address = reg_sel[base];
                        consumed++;
                    }
                    else //SIB General Mode
                    {
                        //ModRM           0  1
                        //byte   0  1  2  3  4
                        //OPCPDE 0F 38 01 04 44
                        //INS    phaddw mm0, qword ptr [rsp+rax*2]
                        address = reg_sel[base] + (reg_sel[index] * factor);
                        consumed++;
                    }
                }
            }
            else if (mod == 1) //mod field = 01b
            {
                if (index == 4) // Index Register = ESP
                {
                    //ModRM           0  1  2
                    //BYTE   0  1  2  3  4  5
                    //OPCPDE 0F 38 01 44 27 80
                    //INS    phaddw mm0, qword ptr [rdi-80h]
                    //PTR = BASE REG + (DISP8 OFFSET)
                    address = reg_sel[base] + *((int8_t*)&ModRM[2]);
                    consumed+= 2;
                }
                else //SIB General Mode
                {
                    //ModRM           0  1  2
                    //BYTE   0  1  2  3  4  5
                    //OPCPDE 0F 38 01 44 44 80
                    //INS    phaddw mm0, qword ptr [rsp+rax*2-80h]
                    //PTR = BASE REG + (INDEX REG * SCALE) + (DISP8 OFFSET)
                    address = reg_sel[base] + (reg_sel[index] * factor) + *((int8_t*)&ModRM[2]);
                    consumed+= 2;
                }
            }
            else if (mod == 2) //mod field = 10b
            {
                if (index == 4) // Index Register = ESP
                {
                    //ModRM           0  1  2  3  4  5
                    //BYTE   0  1  2  3  4  5  6  7  8
                    //OPCPDE 0F 38 01 84 20 04 03 02 01
                    //INS    phaddw mm0, qword ptr [rax+1020304h]
                    //PTR = BASE REG + (DISP32 OFFSET)
                    address = reg_sel[base] + *((uint32_t*)&ModRM[2]);
                    consumed += 5;
                }
                else //SIB General Mode
                {
                    //ModRM           0  1  2  3  4  5
                    //BYTE   0  1  2  3  4  5  6  7  8
                    //OPCPDE 0F 38 01 84 44 04 03 02 01
                    //INS    phaddw mm0, qword ptr [rsp+rax*2+1020304h]
                    //PTR = BASE REG + (INDEX REG * SCALE) + (DISP32 OFFSET)
                    address = reg_sel[base] + (reg_sel[index] * factor) + *((uint32_t*)&ModRM[2]);
                    consumed += 5;
                }
            }
        }
        /*** R/M = EBP in mod 0 Use Disp32 Offset ***/
        else if (num_src == 5)
        {
            if (mod == 0) //mod field = 00b
            {
                //ModRM           0  1  2  3  4
                //BYTE   0  1  2  3  4  5  6  7
                //OPCPDE 0F 38 01 05 01 02 03 04
                //INS    phaddw mm0, qword ptr [cs:04030201h]
                //PTR = DISP32 OFFSET
                address = *((uint32_t*)&ModRM[1]);
                consumed += 4;
            }
        }
        /*** General Mode ***/
        else
        {
            if (mod == 0) //mod field = 00b
            {
                //ModRM           0
                //BYTE   0  1  2  3
                //OPCPDE 0F 38 01 03
                //INS    phaddw mm0, qword [ds:rbx]
                address = reg_sel[num_src];
            }
            else if (mod == 1) //mod field = 01b
            {
                //ModRM           0  1
                //BYTE   0  1  2  3  4
                //OPCPDE 0F 38 01 43 01
                //INS    phaddw mm0, qword [ds:rbx+0x1]
                //PTR = R/M REG + (DISP8 OFFSET)
                address = reg_sel[num_src] + *((int8_t*)&ModRM[1]);
                consumed++;
            }
            else if (mod == 2) //mod field = 10b
            {
                //ModRM           0  1  2  3  4
                //BYTE   0  1  2  3  4  5  6  7
                //OPCPDE 0F 38 01 83 01 02 03 04
                //INS    phaddw mm0, qword [ds:rbx+0x4030201]
                //PTR = R/M REG + (DISP32 OFFSET)
                address = reg_sel[num_src] + *((uint32_t*)&ModRM[1]);
                consumed += 4;
            }
        }

        // address is good now, do read and store operands.
        uint64_t addr = address;

        if (fisttp == 1) //fild 0x66 0xDB
        {
            *(int *)addr = fisttpl((double *)addr);
        }
        else if (fisttp == 2) //fld 0x66 0xDD
        {
            *(long long *)addr = fisttpq((long double *)addr);
        }
        else if (fisttp == 3) //fild 0x66 0xDF
        {
            *(short *)addr = fisttps((float *)addr);
        }
        else //fisttp = 0
        {
            if(kernel_trap)
            {
                if(size_128) ((ssp_m128*)src)->ui = *((__uint128_t*)addr);
                else ((ssp_m64*)src)->u64 = *((uint64_t*)addr);
            }
            else
            {
                //printf("xnu: da = %llx, rsp=%llx,  rip=%llx\n", address, reg_sel[4], r32->eip);
                if(size_128) copyin(addr, (char*) &((ssp_m128*)src)->ui, 16);
                else copyin(addr, (char*) &((ssp_m64*)src)->u64, 8);
            }
        }
    }
    //AnV - Implemented 32-bit fetch END
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
            asm __volatile__ ("movdqu %%xmm0, %0" : "=m" (*v->s8));
            break;
        case 1:
            asm __volatile__ ("movdqu %%xmm1, %0" : "=m" (*v->s8));
            break;
        case 2:
            asm __volatile__ ("movdqu %%xmm2, %0" : "=m" (*v->s8));
            break;
        case 3:
            asm __volatile__ ("movdqu %%xmm3, %0" : "=m" (*v->s8));
            break;
        case 4:
            asm __volatile__ ("movdqu %%xmm4, %0" : "=m" (*v->s8));
            break;
        case 5:
            asm __volatile__ ("movdqu %%xmm5, %0" : "=m" (*v->s8));
            break;
        case 6:
            asm __volatile__ ("movdqu %%xmm6, %0" : "=m" (*v->s8));
            break;
        case 7:
            asm __volatile__ ("movdqu %%xmm7, %0" : "=m" (*v->s8));
            break;
#ifdef __x86_64__
        case 8:
            asm __volatile__ ("movdqu %%xmm8, %0" : "=m" (*v->s8));
            break;
        case 9:
            asm __volatile__ ("movdqu %%xmm9, %0" : "=m" (*v->s8));
            break;
        case 10:
            asm __volatile__ ("movdqu %%xmm10, %0" : "=m" (*v->s8));
            break;
        case 11:
            asm __volatile__ ("movdqu %%xmm11, %0" : "=m" (*v->s8));
            break;
        case 12:
            asm __volatile__ ("movdqu %%xmm12, %0" : "=m" (*v->s8));
            break;
        case 13:
            asm __volatile__ ("movdqu %%xmm13, %0" : "=m" (*v->s8));
            break;
        case 14:
            asm __volatile__ ("movdqu %%xmm14, %0" : "=m" (*v->s8));
            break;
        case 15:
            asm __volatile__ ("movdqu %%xmm15, %0" : "=m" (*v->s8));
            break;
#endif
    }
}

/* get value from the mm register i  */
void getmm(ssp_m64 *v, unsigned int i)
{
    switch(i) {
        case 0:
            asm __volatile__ ("movq %%mm0, %0" : "=m" (*v->s8));
            break;
        case 1:
            asm __volatile__ ("movq %%mm1, %0" : "=m" (*v->s8));
            break;
        case 2:
            asm __volatile__ ("movq %%mm2, %0" : "=m" (*v->s8));
            break;
        case 3:
            asm __volatile__ ("movq %%mm3, %0" : "=m" (*v->s8));
            break;
        case 4:
            asm __volatile__ ("movq %%mm4, %0" : "=m" (*v->s8));
            break;
        case 5:
            asm __volatile__ ("movq %%mm5, %0" : "=m" (*v->s8));
            break;
        case 6:
            asm __volatile__ ("movq %%mm6, %0" : "=m" (*v->s8));
            break;
        case 7:
            asm __volatile__ ("movq %%mm7, %0" : "=m" (*v->s8));
            break;
    }
}

/* move value over to xmm register i */
void movxmm(ssp_m128 *v, unsigned int i)
{
    switch(i) {
        case 0:
            asm __volatile__ ("movdqu %0, %%xmm0" :: "m" (*v->s8) );
            break;
        case 1:
            asm __volatile__ ("movdqu %0, %%xmm1" :: "m" (*v->s8) );
            break;
        case 2:
            asm __volatile__ ("movdqu %0, %%xmm2" :: "m" (*v->s8) );
            break;
        case 3:
            asm __volatile__ ("movdqu %0, %%xmm3" :: "m" (*v->s8) );
            break;
        case 4:
            asm __volatile__ ("movdqu %0, %%xmm4" :: "m" (*v->s8) );
            break;
        case 5:
            asm __volatile__ ("movdqu %0, %%xmm5" :: "m" (*v->s8) );
            break;
        case 6:
            asm __volatile__ ("movdqu %0, %%xmm6" :: "m" (*v->s8) );
            break;
        case 7:
            asm __volatile__ ("movdqu %0, %%xmm7" :: "m" (*v->s8) );
            break;
#ifdef __x86_64__
        case 8:
            asm __volatile__ ("movdqu %0, %%xmm8" :: "m" (*v->s8) );
            break;
        case 9:
            asm __volatile__ ("movdqu %0, %%xmm9" :: "m" (*v->s8) );
            break;
        case 10:
            asm __volatile__ ("movdqu %0, %%xmm10" :: "m" (*v->s8) );
            break;
        case 11:
            asm __volatile__ ("movdqu %0, %%xmm11" :: "m" (*v->s8) );
            break;
        case 12:
            asm __volatile__ ("movdqu %0, %%xmm12" :: "m" (*v->s8) );
            break;
        case 13:
            asm __volatile__ ("movdqu %0, %%xmm13" :: "m" (*v->s8) );
            break;
        case 14:
            asm __volatile__ ("movdqu %0, %%xmm14" :: "m" (*v->s8) );
            break;
        case 15:
            asm __volatile__ ("movdqu %0, %%xmm15" :: "m" (*v->s8) );
            break;
#endif
    }
}

/* move value over to mm register i */
void movmm(ssp_m64 *v, unsigned int i)
{
    switch(i) {
        case 0:
            asm __volatile__ ("movq %0, %%mm0" :: "m" (*v->s8) );
            break;
        case 1:
            asm __volatile__ ("movq %0, %%mm1" :: "m" (*v->s8) );
            break;
        case 2:
            asm __volatile__ ("movq %0, %%mm2" :: "m" (*v->s8) );
            break;
        case 3:
            asm __volatile__ ("movq %0, %%mm3" :: "m" (*v->s8) );
            break;
        case 4:
            asm __volatile__ ("movq %0, %%mm4" :: "m" (*v->s8) );
            break;
        case 5:
            asm __volatile__ ("movq %0, %%mm5" :: "m" (*v->s8) );
            break;
        case 6:
            asm __volatile__ ("movq %0, %%mm6" :: "m" (*v->s8) );
            break;
        case 7:
            asm __volatile__ ("movq %0, %%mm7" :: "m" (*v->s8) );
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
