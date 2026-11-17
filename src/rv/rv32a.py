# RV32A - Atomic Memory Operations (word)

import rv.rvprotoinstrs as rvprotoinstrs

RV32A_OPCODE_AMO = 0b0101111
RV32A_FUNCT3_W   = 0b010

# funct5 codes
RV32A_FUNCT5_LR      = 0b00010
RV32A_FUNCT5_SC      = 0b00011
RV32A_FUNCT5_AMOSWAP = 0b00001
RV32A_FUNCT5_AMOADD  = 0b00000
RV32A_FUNCT5_AMOXOR  = 0b00100
RV32A_FUNCT5_AMOAND  = 0b01100
RV32A_FUNCT5_AMOOR   = 0b01000
RV32A_FUNCT5_AMOMIN  = 0b10000
RV32A_FUNCT5_AMOMAX  = 0b10100
RV32A_FUNCT5_AMOMINU = 0b11000
RV32A_FUNCT5_AMOMAXU = 0b11100

def _amo_funct7(funct5: int, aq: int, rl: int):
    return (funct5 << 2) | (aq << 1) | rl

# LR.W: rd = Load-Reserved from [rs1], rs2 is unused (0)
def rv32a_lr_w(rd: int, rs1: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV32A_OPCODE_AMO, rd, RV32A_FUNCT3_W, rs1, 0, _amo_funct7(RV32A_FUNCT5_LR, aq, rl))

# SC.W: Store-Conditional rs2 to [rs1], rd = success/fail
def rv32a_sc_w(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV32A_OPCODE_AMO, rd, RV32A_FUNCT3_W, rs1, rs2, _amo_funct7(RV32A_FUNCT5_SC, aq, rl))

def rv32a_amoswap_w(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV32A_OPCODE_AMO, rd, RV32A_FUNCT3_W, rs1, rs2, _amo_funct7(RV32A_FUNCT5_AMOSWAP, aq, rl))

def rv32a_amoadd_w(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV32A_OPCODE_AMO, rd, RV32A_FUNCT3_W, rs1, rs2, _amo_funct7(RV32A_FUNCT5_AMOADD, aq, rl))

def rv32a_amoxor_w(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV32A_OPCODE_AMO, rd, RV32A_FUNCT3_W, rs1, rs2, _amo_funct7(RV32A_FUNCT5_AMOXOR, aq, rl))

def rv32a_amoand_w(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV32A_OPCODE_AMO, rd, RV32A_FUNCT3_W, rs1, rs2, _amo_funct7(RV32A_FUNCT5_AMOAND, aq, rl))

def rv32a_amoor_w(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV32A_OPCODE_AMO, rd, RV32A_FUNCT3_W, rs1, rs2, _amo_funct7(RV32A_FUNCT5_AMOOR, aq, rl))

def rv32a_amomin_w(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV32A_OPCODE_AMO, rd, RV32A_FUNCT3_W, rs1, rs2, _amo_funct7(RV32A_FUNCT5_AMOMIN, aq, rl))

def rv32a_amomax_w(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV32A_OPCODE_AMO, rd, RV32A_FUNCT3_W, rs1, rs2, _amo_funct7(RV32A_FUNCT5_AMOMAX, aq, rl))

def rv32a_amominu_w(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV32A_OPCODE_AMO, rd, RV32A_FUNCT3_W, rs1, rs2, _amo_funct7(RV32A_FUNCT5_AMOMINU, aq, rl))

def rv32a_amomaxu_w(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV32A_OPCODE_AMO, rd, RV32A_FUNCT3_W, rs1, rs2, _amo_funct7(RV32A_FUNCT5_AMOMAXU, aq, rl))
