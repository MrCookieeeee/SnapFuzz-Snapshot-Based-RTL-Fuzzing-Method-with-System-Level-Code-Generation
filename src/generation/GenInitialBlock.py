from generation.InstructionsCfClass import *

from rv.csrids import CSR_IDS
from generation.Instructions import ISAInstrClass

from pick.CreateInstr import create_instr


from params.fuzzparams import RELOCATOR_REGISTER_ID, BASIC_BLOCK_MIN_SPACE, INITIAL_BLOCK_MAX_SIZE_BYTES, TRAP_HANDLER_TMP_ID
from params.runparams import DO_ASSERT

from generation.Instructions import get_range_bits_per_instrclass, ISAInstrClass

from initialstate.FuzzerState import FuzzerState

import random


class _InitialTrapGuard:
    """Reject an unexpected trap in both Spike and RTL, before fuzzing starts."""
    instr_str = "InitialTrapGuard"
    iscompressed = False

    def gen_bytecode_int(self, is_spike_resolution):
        return rv32i_bne(1, 0, 0)


def _gen_translated_fetch_chain(fuzzerstate, curr_addr):
    """Visit distinct executable pages in U-mode, then return through ECALL."""
    if not fuzzerstate.design_has_user_mode:
        return []

    boundaries = []
    # Keep every jump within JAL's range and outside the initial reservation.
    for boundary in range(4096, min(fuzzerstate.memsize, 1 << 20), 4096):
        if fuzzerstate.memview.is_mem_range_free(boundary - 4, boundary + 4):
            fuzzerstate.memview.alloc_mem_range(boundary - 4, boundary + 4)
            boundaries.append(boundary)
            if len(boundaries) == 40:
                break
    if not boundaries:
        return []

    is_64bit = fuzzerstate.is_design_64bit
    for index, boundary in enumerate(boundaries):
        fuzzerstate.block_tail_instrs.append((
            RegImmInstruction("addi", 0, 0, 0, is_64bit), boundary - 4))
        if index + 1 < len(boundaries):
            instr = JALInstruction("jal", 0, boundaries[index + 1] - 4 - boundary, is_64bit)
        else:
            instr = EcallEbreakInstruction("ecall")
        fuzzerstate.block_tail_instrs.append((instr, boundary))

    entry_addr = curr_addr + 8 * 4
    resume_addr = entry_addr + 4
    # MRET clears MPRV on descent. Restore the original mstatus after ECALL
    # so the normal generated data accesses still use MPRV translation.
    return [
        CSRRegInstruction("csrrs", 3, 0, CSR_IDS.MSTATUS),
        RegImmInstruction("addi", 1, RELOCATOR_REGISTER_ID, entry_addr, is_64bit),
        CSRRegInstruction("csrrw", 0, 1, CSR_IDS.MEPC),
        RegImmInstruction("addi", 1, RELOCATOR_REGISTER_ID, resume_addr, is_64bit),
        CSRRegInstruction("csrrw", 2, 1, CSR_IDS.MTVEC),
        # Machine interrupts are globally eligible in U-mode even with MIE=0
        # in mstatus. Mask their individual enables for this ECALL excursion.
        CSRRegInstruction("csrrw", 4, 0, CSR_IDS.MIE),
        CSRRegInstruction("csrrc", 0, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS),
        SimpleExceptionEncapsulator(True, None, PrivilegeDescentInstruction(True)),
        SimpleExceptionEncapsulator(True, None, JALInstruction(
            "jal", 0, boundaries[0] - 4 - entry_addr, is_64bit)),
        CSRRegInstruction("csrrs", 1, 0, CSR_IDS.MCAUSE),
        RegImmInstruction("addi", 1, 1, -8, is_64bit),
        _InitialTrapGuard(),
        CSRRegInstruction("csrrw", 0, 2, CSR_IDS.MTVEC),
        CSRRegInstruction("csrrw", 0, 0, CSR_IDS.MEPC),
        CSRRegInstruction("csrrw", 0, 0, CSR_IDS.MCAUSE),
        CSRRegInstruction("csrrw", 0, 0, CSR_IDS.MTVAL),
        CSRRegInstruction("csrrw", 0, 4, CSR_IDS.MIE),
        CSRRegInstruction("csrrw", 0, 3, CSR_IDS.MSTATUS),
    ]


def gen_initial_basic_block(fuzzerstate: 'FuzzerState', spike_startaddr):
    fuzzerstate.init_new_bb() 

    curr_addr = fuzzerstate.curr_bb_start_addr # now is 0
    
    lui_imm, addi_imm = li_into_reg(spike_startaddr, False) 
    fuzzerstate.instr_objs_seq[-1].append(ImmRdInstruction("lui", RELOCATOR_REGISTER_ID, lui_imm, fuzzerstate.is_design_64bit))
    fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", RELOCATOR_REGISTER_ID, RELOCATOR_REGISTER_ID, addi_imm, fuzzerstate.is_design_64bit))
    # Clear the top 32 bits, 32bit design no need, because lui will clear the lower 32bit
    if fuzzerstate.is_design_64bit:
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("slli", RELOCATOR_REGISTER_ID, RELOCATOR_REGISTER_ID, 32, fuzzerstate))
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("srli", RELOCATOR_REGISTER_ID, RELOCATOR_REGISTER_ID, 32, fuzzerstate))
    curr_addr += 8 + 8*int(fuzzerstate.is_design_64bit)

    if DO_ASSERT:
        assert curr_addr == fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4 # NO_COMPRESSED
    
    # --------------------------------------------       
    # Set medegeg stvec to zero
    # --------------------------------------------       
    # Write 0 to medeleg to uniformize across designs. This must be done in initialblock to facilitate the analysis.
    if fuzzerstate.design_has_supervisor_mode:
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 0, CSR_IDS.MEDELEG))
        curr_addr += 4

    # Write 0 to stvec to uniformize across designs. This must be done in initialblock to facilitate the analysis.
    if fuzzerstate.design_has_supervisor_mode:
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 0, CSR_IDS.STVEC))
        curr_addr += 4
   
    # --------------------------------------------       
    # Set mtvec to trap_handler
    # --------------------------------------------     
    reg_id = TRAP_HANDLER_TMP_ID # s10
    csr_id = CSR_IDS.MTVEC

    # a0 <- trap_handler_base_addr
    lui_imm, addi_imm = li_into_reg(fuzzerstate.trap_handler_bb_base_addr + fuzzerstate.design_base_addr, False)
    fuzzerstate.instr_objs_seq[-1].append(ImmRdInstruction("lui", reg_id, lui_imm, fuzzerstate.is_design_64bit))
    fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", reg_id, reg_id, addi_imm, fuzzerstate.is_design_64bit))
    curr_addr += 8

    # Clear the top 32 bits of a0, or it will be 0xffffffff...
    if fuzzerstate.is_design_64bit:
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("slli", reg_id, reg_id, 32, fuzzerstate.is_design_64bit))
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("srli", reg_id, reg_id, 32, fuzzerstate.is_design_64bit))
        curr_addr += 8

    # mtvec <- a0
    fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, reg_id, csr_id))
    curr_addr += 4
    
    # --------------------------------------------       
    # Set PMP region
    # --------------------------------------------       
    if fuzzerstate.design_has_pmp and (
            fuzzerstate.design_name not in ("rocket", "boom")
            or fuzzerstate.memory_expansion_enabled):
        pmp_index = ((fuzzerstate.randseed >> 3) & 7
                     if fuzzerstate.design_name == "boom" else 0)
        # pmpcfg0
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", 1, 0, 31, fuzzerstate.is_design_64bit))
        if pmp_index:
            fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("slli", 1, 1, 8 * pmp_index, fuzzerstate.is_design_64bit))
            curr_addr += 4
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 1, CSR_IDS.PMPCFG0))
        curr_addr += 8
        # PMP address
        if fuzzerstate.is_design_64bit:
            fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", 1, 0, 1, fuzzerstate.is_design_64bit))
            fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("slli", 1, 0, 0x36, fuzzerstate.is_design_64bit))
            fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", 1, 1, -1, fuzzerstate.is_design_64bit))
            fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 1, CSR_IDS.PMPADDR0 + pmp_index))
            curr_addr += 16
        else:
            fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", 1, 0, -1, fuzzerstate.is_design_64bit))
            fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 1, CSR_IDS.PMPADDR0))
            curr_addr += 8

    if fuzzerstate.design_name == "boom" and not (fuzzerstate.randseed & 2):
        # Clear the boot ROM's pending machine software interrupt before VM setup.
        clint_add = bool(fuzzerstate.randseed & 4)
        clint_setup = [
            ImmRdInstruction("lui", 1, 0x2000, fuzzerstate.is_design_64bit),
            SimpleExceptionEncapsulator(True, None, IntStoreInstruction(
                "sw", 1, 0, 0, -1, fuzzerstate.is_design_64bit)),
            SpecialInstruction("fence"),
            # Exercise uncached atomic access with checked old and restored values.
            ImmRdInstruction("lui", 5, 0x2004, fuzzerstate.is_design_64bit),
            RegImmInstruction("addi", 2, 0, -1, fuzzerstate.is_design_64bit),
            SimpleExceptionEncapsulator(True, None, IntStoreInstruction(
                "sd", 5, 2, 0, -1, fuzzerstate.is_design_64bit)),
            SpecialInstruction("fence"),
            RegImmInstruction("addi", 2, 0, 1 if clint_add else -1, fuzzerstate.is_design_64bit),
            SimpleExceptionEncapsulator(True, None, AtomicInstruction(
                "amoadd.d" if clint_add else "amoswap.w", 1, 5, 2, 0, 0, -1, fuzzerstate.is_design_64bit)),
            RegImmInstruction("addi", 1, 1, 1, fuzzerstate.is_design_64bit),
            _InitialTrapGuard(),
            SimpleExceptionEncapsulator(True, None, IntLoadInstruction(
                "ld", 1, 5, 0, -1, fuzzerstate.is_design_64bit)),
            RegImmInstruction("addi", 1, 1, 0 if clint_add else 1, fuzzerstate.is_design_64bit),
            _InitialTrapGuard(),
            RegImmInstruction("addi", 2, 0, -1, fuzzerstate.is_design_64bit),
            SimpleExceptionEncapsulator(True, None, IntStoreInstruction(
                "sd", 5, 2, 0, -1, fuzzerstate.is_design_64bit)),
            SpecialInstruction("fence"),
            SimpleExceptionEncapsulator(True, None, IntLoadInstruction(
                "ld", 1, 5, 0, -1, fuzzerstate.is_design_64bit)),
            RegImmInstruction("addi", 1, 1, 1, fuzzerstate.is_design_64bit),
            _InitialTrapGuard(),
            ImmRdInstruction("lui", 5, 0xc000, fuzzerstate.is_design_64bit),
            SimpleExceptionEncapsulator(True, None, IntLoadInstruction(
                "ld", 1, 5, 0, -1, fuzzerstate.is_design_64bit)),
            _InitialTrapGuard(),
        ]
        fuzzerstate.instr_objs_seq[-1].extend(clint_setup)
        curr_addr += 4 * len(clint_setup)

    # --------------------------------------------       
    # Initial CSR to 0
    # --------------------------------------------       
    if fuzzerstate.is_design_64bit:
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 0, CSR_IDS.MCYCLE))
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 0, CSR_IDS.MCAUSE))
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 0, CSR_IDS.MTVAL))
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 0, CSR_IDS.MSCRATCH))
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 0, CSR_IDS.MINSTRET))
        curr_addr += 20

    else:
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 0, CSR_IDS.MCYCLEH))
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 0, CSR_IDS.MINSTRET))
        curr_addr += 8

    if fuzzerstate.design_has_supervisor_mode:
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 0, CSR_IDS.SCAUSE))
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 0, CSR_IDS.STVAL))
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 0, CSR_IDS.SSCRATCH))
        curr_addr += 12


    # --------------------------------------------       
    # Prepare FS
    # --------------------------------------------       
    if fuzzerstate.design_has_fpu:
        # Set FS to Clean (mstatus[14:13] = 10)
        fuzzerstate.instr_objs_seq[-1].append(ImmRdInstruction("lui", FPU_ENDIS_REGISTER_ID, 0b10, fuzzerstate.is_design_64bit))
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, FPU_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))

        # Set the initial rounding mode to 0 initially, arbitrarily. 
        # We arbitrarily use the register x1 as an intermediate register
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", 1, 0, 0, fuzzerstate.is_design_64bit))
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 1, CSR_IDS.FCSR))
        curr_addr += 16 # NO_COMPRESSED
    
    # --------------------------------------------       
    # Prepare MPP
    # --------------------------------------------   
    if fuzzerstate.design_has_supervisor_mode or fuzzerstate.design_has_user_mode:
        # MPP_TOP_ENDIS_REGISTER   MPP[12]    = 1
        # MPP_BOTH_ENDIS_REGISTER  MPP[12:11] = 1
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("srli", MPP_TOP_ENDIS_REGISTER_ID, FPU_ENDIS_REGISTER_ID, 1, fuzzerstate.is_design_64bit))
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("srli", MPP_BOTH_ENDIS_REGISTER_ID, FPU_ENDIS_REGISTER_ID, 2, fuzzerstate.is_design_64bit))
        fuzzerstate.instr_objs_seq[-1].append(R12DInstruction("or", MPP_BOTH_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID))
        
        curr_addr += 12 # NO_COMPRESSED
  
        # While it is not necesary to set the mpp initially, it is convenient to do so. If we don't, then we should adapt the initial values (typically to None) in privilegestate.py
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrs", 0, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrs", 0, MPP_TOP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))
        curr_addr += 8 # NO_COMPRESSED
    
    # --------------------------------------------       
    # Setup virtual memory (Sv39 identity mapping)
    # Enable MPRV so data accesses go through VM translation
    # --------------------------------------------       
    if fuzzerstate.vm_enabled:
        pt_phys = fuzzerstate.design_base_addr + fuzzerstate.page_table_base_offset
        ppn = pt_phys >> 12

        # x1 = Sv39 mode (8 << 60)
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", 1, 0, 8, fuzzerstate.is_design_64bit))
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("slli", 1, 1, 60, fuzzerstate.is_design_64bit))
        curr_addr += 8

        # x2 = PPN of page table root
        lui_imm_pt, addi_imm_pt = li_into_reg(ppn, False)
        fuzzerstate.instr_objs_seq[-1].append(ImmRdInstruction("lui", 2, lui_imm_pt, fuzzerstate.is_design_64bit))
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", 2, 2, addi_imm_pt, fuzzerstate.is_design_64bit))
        # Clear upper 32 bits
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("slli", 2, 2, 32, fuzzerstate.is_design_64bit))
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("srli", 2, 2, 32, fuzzerstate.is_design_64bit))
        curr_addr += 16

        # x1 = SATP = mode | PPN
        fuzzerstate.instr_objs_seq[-1].append(R12DInstruction("or", 1, 1, 2))
        curr_addr += 4

        # Write SATP
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 1, CSR_IDS.SATP))
        curr_addr += 4

        # Flush TLB
        fuzzerstate.instr_objs_seq[-1].append(SfenceVmaInstruction("sfence.vma", 0, 0))
        curr_addr += 4

        # Set MPRV and SUM so U/S effective accesses can use the mapped user pages.
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", 1, 0, 3, fuzzerstate.is_design_64bit))
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("slli", 1, 1, 17, fuzzerstate.is_design_64bit))
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrs", 0, 1, CSR_IDS.MSTATUS))
        curr_addr += 12

        # Set MPP=U (clear bits 12:11) for U-mode translation via MPRV
        fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrc", 0, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))
        curr_addr += 4

        fetch_setup = _gen_translated_fetch_chain(fuzzerstate, curr_addr)
        fuzzerstate.instr_objs_seq[-1].extend(fetch_setup)
        curr_addr += 4 * len(fetch_setup)
    
    # Right now, SnapFuzz dont support S-mode, so I use this reg for trap handler
    # SPP设置   
    #     if fuzzerstate.design_has_user_mode:
    #         fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("srli", SPP_ENDIS_REGISTER_ID, FPU_ENDIS_REGISTER_ID, 5, fuzzerstate.is_design_64bit))
    #         curr_addr += 4 # NO_COMPRESSED
    #         # While it is not necesary to set the mpp initially, it is convenient to do so. If we don't, then we should adapt the initial values (typically to None) in privilegestate.py
    #         fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrs", 0, SPP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))
    #         curr_addr += 4 # NO_COMPRESSED
    
    # ----------------------------------------------------------------------------------------              
    # Set RDEP_MASK_REGISTER_ID=0x00000000FFFFFFFF
    # For 64bit design, we calculate the addr, we only use 32bit, so we mask 64bit reg to 32bit
    # ----------------------------------------------------------------------------------------       
    if fuzzerstate.is_design_64bit:
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", RDEP_MASK_REGISTER_ID, 0, -1, fuzzerstate.is_design_64bit))
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("slli", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, 32, fuzzerstate.is_design_64bit))
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("xori", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, -1, fuzzerstate.is_design_64bit))
        curr_addr += 12 # NO_COMPRESSED
        if DO_ASSERT:
            assert curr_addr == fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4 # NO_COMPRESSED

    # Set the last pickable reg to 0x80000000 first, then add a bias and set it to initial random value addr 
    fuzzerstate.instr_objs_seq[-1].append(R12DInstruction("add", fuzzerstate.num_pickable_regs-1, 0, RELOCATOR_REGISTER_ID))
    curr_addr += 4

    # align to 8 byte for ld and fld
    if fuzzerstate.design_has_fpu:
        # 1 is for the last jal instr
        random_data_start_addr_before_padding = curr_addr + 4*(fuzzerstate.num_pickable_regs + fuzzerstate.num_pickable_floating_regs + 1)
        expect_padding = bool(random_data_start_addr_before_padding & 0x7 == 4) 
    else:
        random_data_start_addr_before_padding = curr_addr + 4*(fuzzerstate.num_pickable_regs + 1)
        expect_padding = bool(random_data_start_addr_before_padding & 0x7 == 4) 

    # For next "fld	ft0,192(reg)", we have to make sure 192 is 8 byte aligned
    if expect_padding:
        random_data_start_addr_after_padding = random_data_start_addr_before_padding + 4
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", 0, 0, 0, fuzzerstate.is_design_64bit))
        curr_addr += 4
    else:
        random_data_start_addr_after_padding = random_data_start_addr_before_padding

    # add random data start addr to the last pickable reg
    fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", fuzzerstate.num_pickable_regs-1, fuzzerstate.num_pickable_regs-1, random_data_start_addr_after_padding, fuzzerstate.is_design_64bit))
    curr_addr += 4

    # Floating loads must be done before int loads, because the last pickable int register will be overwritten.
    if fuzzerstate.design_has_fpu:
        if DO_ASSERT:
            assert fuzzerstate.num_pickable_floating_regs <= fuzzerstate.num_pickable_regs, "For this param choice, we need to adapt slightly the initial block."
        for fp_reg_id in range(fuzzerstate.num_pickable_floating_regs):
            fuzzerstate.instr_objs_seq[-1].append(FloatLoadInstruction("fld" if fuzzerstate.is_design_64bit else "flw", fp_reg_id, fuzzerstate.num_pickable_regs-1, 8*(fp_reg_id+fuzzerstate.num_pickable_regs-1), -1, fuzzerstate.is_design_64bit))
            curr_addr += 4
    for reg_id in range(1, fuzzerstate.num_pickable_regs):
        fuzzerstate.instr_objs_seq[-1].append(IntLoadInstruction("ld" if fuzzerstate.is_design_64bit else "lw", reg_id, fuzzerstate.num_pickable_regs-1, 8*(reg_id-1), -1, fuzzerstate.is_design_64bit))
        curr_addr += 4

    if DO_ASSERT:
        assert curr_addr == fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4, f"{curr_addr}, {fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4}" # NO_COMPRESSED

    # generate initial random value for reg
    num_reginit_vals = fuzzerstate.num_pickable_regs-1
    if fuzzerstate.design_has_fpu:
        num_reginit_vals += fuzzerstate.num_pickable_floating_regs
    for _ in range(num_reginit_vals):
        fuzzerstate.initial_reg_data_content.append(0 if random.random() < fuzzerstate.proba_reg_starts_with_zero else random.randrange(1 << 64))

    if fuzzerstate.design_has_fpu and fuzzerstate.is_design_64bit:
        fp_corner_values = (
            0x0000000000000000, 0x8000000000000000,
            0x3ff0000000000000, 0xbff0000000000000, 0x3ff0000000000001,
            0x0010000000000000, 0x000fffffffffffff, 0x0000000000000001,
            0x7fefffffffffffff, 0x7ff0000000000000, 0xfff0000000000000,
            0x7ff8000000000000, 0x7ff0000000000001,
            0xffffffff00000000, 0xffffffff80000000,
            0xffffffff3f800000, 0xffffffffbf800000, 0xffffffff3f800001,
            0xffffffff00800000, 0xffffffff007fffff, 0xffffffff00000001,
            0xffffffff7f7fffff, 0xffffffff7f800000, 0xffffffffff800000,
            0xffffffff7fc00000, 0xffffffff7f800001,
        )
        for reginit_id in range(fuzzerstate.num_pickable_regs - 1, num_reginit_vals):
            if random.random() < 0.5:
                fuzzerstate.initial_reg_data_content[reginit_id] = random.choice(fp_corner_values)
    
    # alloc memory for initialblock
    intended_initial_block_plus_reginit_size = len(fuzzerstate.instr_objs_seq[-1]) * 4 + 4 + len(fuzzerstate.initial_reg_data_content) * 8 + int(expect_padding) * 4  # NO_COMPRESSED
    if DO_ASSERT:
        assert intended_initial_block_plus_reginit_size + 4 <= INITIAL_BLOCK_MAX_SIZE_BYTES * 4
    fuzzerstate.memview.alloc_mem_range(fuzzerstate.curr_bb_start_addr, fuzzerstate.curr_bb_start_addr+intended_initial_block_plus_reginit_size+4) # NO_COMPRESSED
    
    # Jump to the next basic block, say, with jal for simplicity
    # bits range: jar=20bit jalr=32bit 
    range_bits_each_direction = get_range_bits_per_instrclass(ISAInstrClass.JAL)
    fuzzerstate.next_bb_addr = fuzzerstate.memview.gen_random_free_addr(4, BASIC_BLOCK_MIN_SPACE, curr_addr - (1 << range_bits_each_direction), curr_addr + (1 << range_bits_each_direction))
    if fuzzerstate.next_bb_addr is None:
        return False
    
    new_instr, iscompressed = create_instr("jal", fuzzerstate, curr_addr)
    fuzzerstate.instr_objs_seq[-1].append(new_instr)

    # NOTICE: We could have compressed instr here, but we don't consider +2/+4, because it induce no wrong behavior
    curr_addr += 4

    # initial_reg_data_addr is for reg randomize, and is located right after the initial block
    fuzzerstate.initial_reg_data_addr = curr_addr

    if DO_ASSERT:
        assert curr_addr == random_data_start_addr_after_padding, f"curr_addr={curr_addr}, expected={random_data_start_addr_after_padding}"
        
    curr_addr += 8 * num_reginit_vals

    return True
