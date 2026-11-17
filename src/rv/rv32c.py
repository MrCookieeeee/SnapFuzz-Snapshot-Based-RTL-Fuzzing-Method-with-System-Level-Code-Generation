import rv.rvprotoinstrscompress as rvprotoinstrsc

RV32C_OPCODE_00   = 0b00
RV32C_OPCODE_01   = 0b01
RV32C_OPCODE_10   = 0b10

"""
RV32C:
IntLoadInstructions: C.LWSP, C.LW, 

IntStoreInstructions: C.SWSP, C.SW

FloatLoadInstructions: 

FloatStoreInstructions: 

ImmInstruction: C.BEQZ, C.BNEZ, 

C.JAL, C.J, C.JR, C.JALR, 


R12DInstructions
"""
# =======================
# R12DInstruction
# =======================
def rv32c_mv(rds1: int, rs2: int):
    return rvprotoinstrsc.instruc_crtype(RV32C_OPCODE_10, rs2, rds1, 0b1000)

def rv32c_add(rds1: int, rs2: int):
    return rvprotoinstrsc.instruc_crtype(RV32C_OPCODE_10, rs2, rds1, 0b1001)

def rv32c_and(rds1prime: int, rs2prime: int):
    return rvprotoinstrsc.instruc_catype(RV32C_OPCODE_01, rs2prime, 0b11, rds1prime, 0b100011)

def rv32c_or(rds1prime: int, rs2prime: int):
    return rvprotoinstrsc.instruc_catype(RV32C_OPCODE_01, rs2prime, 0b10, rds1prime, 0b100011)

def rv32c_xor(rds1prime: int, rs2prime: int):
    return rvprotoinstrsc.instruc_catype(RV32C_OPCODE_01, rs2prime, 0b01, rds1prime, 0b100011)

def rv32c_sub(rds1prime: int, rs2prime: int):
    return rvprotoinstrsc.instruc_catype(RV32C_OPCODE_01, rs2prime, 0b00, rds1prime, 0b100011)




# =======================
# IntLoadInstruction
# =======================
def rv32c_lw(rdprime: int, rs1prime:int, imm: int):
    return rvprotoinstrsc.instruc_cltype(RV32C_OPCODE_00, rdprime, rs1prime, 0b010, imm)

def rv32c_swsp(rs2: int, imm: int):
    """
    Here we use rs2, becase for a csstype, (now we only have c.swsq, which is 'sw rs2, imm(sp)', here sp is the rs1
    """
    return rvprotoinstrsc.instruc_csstype(RV32C_OPCODE_10, rs2, 0b110, imm)


# ======================
# ImmRdInstruction
# ======================
def rv32c_li(rd: int, imm: int):
    return rvprotoinstrsc.instruc_citype(RV32C_OPCODE_01, rd, 0b010, imm)

def rv32c_lui(rd: int, imm: int):
    return rvprotoinstrsc.instruc_citype(RV32C_OPCODE_01, rd, 0b011, imm)

# ======================
# RegImmInstruction
# ======================
def rv32c_addi(rds1: int, imm: int):
    return rvprotoinstrsc.instruc_citype(RV32C_OPCODE_01, rds1, 0b000, imm) 

def rv32c_addi16sp(rds1: int, imm: int):
    # c.addi16sp rds1 = 2
    return rvprotoinstrsc.instruc_citype(RV32C_OPCODE_01, rds1, 0b011, imm)

def rv32c_addi4spn(rdprime: int, imm: int):
    return rvprotoinstrsc.instruc_ciwtype(RV32C_OPCODE_00, rdprime, 0b000, imm)

def rv32c_slli(rds1: int, imm: int):
    return rvprotoinstrsc.instruc_citype(RV32C_OPCODE_10, rds1, 0b000, imm)

def rv32c_srli(rds1prime: int, imm: int):
    return rvprotoinstrsc.instruc_cbtype_shift_andi(RV32C_OPCODE_01, rds1prime, 0b00, 0b100, imm)

def rv32c_srai(rds1prime: int, imm: int):
    return rvprotoinstrsc.instruc_cbtype_shift_andi(RV32C_OPCODE_01, rds1prime, 0b01, 0b100, imm)

def rv32c_andi(rds1prime: int, imm: int):
    return rvprotoinstrsc.instruc_cbtype_shift_andi(RV32C_OPCODE_01, rds1prime, 0b10, 0b100, imm)


# ===========
# JAL
# ===========
def rv32c_j(imm: int):
    return rvprotoinstrsc.instruc_cjtype(RV32C_OPCODE_01, 0b101, imm)

def rv32c_jal(imm: int):
    return rvprotoinstrsc.instruc_cjtype(RV32C_OPCODE_01, 0b001, imm)

# ===========
# JALR
# ===========
def rv32c_jr(rd: int):
    # for c.jalr, rs2 is not used, so we set it to 0
    return rvprotoinstrsc.instruc_crtype(RV32C_OPCODE_10, 0, rd, 0b1000)

def rv32c_jalr(rd: int):
    # for c.jalr, rs2 is not used, so we set it to 0
    return rvprotoinstrsc.instruc_crtype(RV32C_OPCODE_10, 0, rd, 0b1001)