# RV64A - Atomic Memory Operations (doubleword)

import rv.rvprotoinstrs as rvprotoinstrs

RV64A_OPCODE_AMO = 0b0101111
RV64A_FUNCT3_D   = 0b011

# funct5 codes (same as RV32A)
RV64A_FUNCT5_LR      = 0b00010
RV64A_FUNCT5_SC      = 0b00011
RV64A_FUNCT5_AMOSWAP = 0b00001
RV64A_FUNCT5_AMOADD  = 0b00000
RV64A_FUNCT5_AMOXOR  = 0b00100
RV64A_FUNCT5_AMOAND  = 0b01100
RV64A_FUNCT5_AMOOR   = 0b01000
RV64A_FUNCT5_AMOMIN  = 0b10000
RV64A_FUNCT5_AMOMAX  = 0b10100
RV64A_FUNCT5_AMOMINU = 0b11000
RV64A_FUNCT5_AMOMAXU = 0b11100

def _amo_funct7(funct5: int, aq: int, rl: int):
    return (funct5 << 2) | (aq << 1) | rl

# LR.D: rd = Load-Reserved from [rs1], rs2 is unused (0)
def rv64a_lr_d(rd: int, rs1: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV64A_OPCODE_AMO, rd, RV64A_FUNCT3_D, rs1, 0, _amo_funct7(RV64A_FUNCT5_LR, aq, rl))

# SC.D: Store-Conditional rs2 to [rs1], rd = success/fail
def rv64a_sc_d(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV64A_OPCODE_AMO, rd, RV64A_FUNCT3_D, rs1, rs2, _amo_funct7(RV64A_FUNCT5_SC, aq, rl))

def rv64a_amoswap_d(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV64A_OPCODE_AMO, rd, RV64A_FUNCT3_D, rs1, rs2, _amo_funct7(RV64A_FUNCT5_AMOSWAP, aq, rl))

def rv64a_amoadd_d(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV64A_OPCODE_AMO, rd, RV64A_FUNCT3_D, rs1, rs2, _amo_funct7(RV64A_FUNCT5_AMOADD, aq, rl))

def rv64a_amoxor_d(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV64A_OPCODE_AMO, rd, RV64A_FUNCT3_D, rs1, rs2, _amo_funct7(RV64A_FUNCT5_AMOXOR, aq, rl))

def rv64a_amoand_d(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV64A_OPCODE_AMO, rd, RV64A_FUNCT3_D, rs1, rs2, _amo_funct7(RV64A_FUNCT5_AMOAND, aq, rl))

def rv64a_amoor_d(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV64A_OPCODE_AMO, rd, RV64A_FUNCT3_D, rs1, rs2, _amo_funct7(RV64A_FUNCT5_AMOOR, aq, rl))

def rv64a_amomin_d(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV64A_OPCODE_AMO, rd, RV64A_FUNCT3_D, rs1, rs2, _amo_funct7(RV64A_FUNCT5_AMOMIN, aq, rl))

def rv64a_amomax_d(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV64A_OPCODE_AMO, rd, RV64A_FUNCT3_D, rs1, rs2, _amo_funct7(RV64A_FUNCT5_AMOMAX, aq, rl))

def rv64a_amominu_d(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV64A_OPCODE_AMO, rd, RV64A_FUNCT3_D, rs1, rs2, _amo_funct7(RV64A_FUNCT5_AMOMINU, aq, rl))

def rv64a_amomaxu_d(rd: int, rs1: int, rs2: int, aq: int, rl: int):
    return rvprotoinstrs.instruc_rtype(RV64A_OPCODE_AMO, rd, RV64A_FUNCT3_D, rs1, rs2, _amo_funct7(RV64A_FUNCT5_AMOMAXU, aq, rl))
