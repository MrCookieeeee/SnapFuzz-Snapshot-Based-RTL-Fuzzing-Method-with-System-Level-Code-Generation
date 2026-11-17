from params.runparams import DO_ASSERT

def instruc_rtype(opcode: int, rd: int, funct3: int, rs1: int, rs2: int, funct7: int):
    """
    Args:
        opcode: uint8_t
        rd: uint8_t
        funct3: uint8_t
        rs1: uint8_t
        rs2: uint8_t
        funct7: uint8_t

    Return:
        uint32_t
    """
    if DO_ASSERT:
        assert(opcode >= 0)
        assert(rd >= 0)
        assert(funct3 >= 0)
        assert(rs1 >= 0)
        assert(rs2 >= 0)
        assert(funct7 >= 0)

        assert(opcode < (1 << 7))
        assert(rd < 32)
        assert(funct3 < 8)
        assert(rs1 < 32)
        assert(rs2 < 32)
        assert(funct7 < (1 << 7))

    rd_offset     = 7
    funct3_offset = rd_offset + 5
    rs1_offset    = funct3_offset + 3
    rs2_offset    = rs1_offset + 5
    funct7_offset = rs2_offset + 5

    return opcode | \
        (rd << rd_offset) | \
        (funct3 << funct3_offset) | \
        (rs1 << rs1_offset) | \
        (rs2 << rs2_offset) | \
        (funct7 << funct7_offset)

def instruc_itype(opcode: int, rd: int, funct3: int, rs1: int, imm: int):
    """
    Args:
        opcode: uint8_t
        rd: uint8_t 
        funct3: uint8_t
        rs1: uint8_t
    
    Return:
        uint32_t
    """
    if DO_ASSERT:
        assert(opcode < (1 << 7))
        assert(rd < 32)
        assert(funct3 < 8)
        assert(rs1 < 32)
        # assert(imm < (1 << 12))

        assert(opcode >= 0)
        assert(rd >= 0)
        assert(funct3 >= 0)
        assert(rs1 >= 0)
        # assert(imm >= 0)

    imm = imm & 0b111111111111

    rd_offset     = 7
    funct3_offset = rd_offset + 5
    rs1_offset    = funct3_offset + 3
    imm_offset    = rs1_offset + 5

    return opcode | \
        (rd << rd_offset) | \
        (funct3 << funct3_offset) | \
        (rs1 << rs1_offset) | \
        (imm << imm_offset)

def instruc_stype(opcode: int, funct3: int, rs1: int, rs2: int, imm: int):
    """
    Args:
        opcode: uint8_t
        funct3: uint8_t
        rs1: uint8_t
        rs2: uint8_t

    Return:
        uint32_t
    """
    if DO_ASSERT:
        assert(opcode < (1 << 7))
        assert(funct3 < 8)
        assert(rs1 < 32)
        assert(rs2 < 32)
        # assert(imm < (1 << 12))

        assert(opcode >= 0)
        assert(funct3 >= 0)
        assert(rs1 >= 0)
        assert(rs2 >= 0)
        # assert(imm >= 0)

    imm = imm & 0b111111111111

    imm4_0_offset = 7
    funct3_offset = imm4_0_offset + 5
    rs1_offset = funct3_offset + 3
    rs2_offset = rs1_offset + 5
    imm11_5_offset = rs2_offset + 5

    imm4_0 = imm & 0b11111
    imm11_5 = (imm >> 5) & 0b1111111

    return opcode | \
        (imm4_0 << imm4_0_offset) | \
        (funct3 << funct3_offset) | \
        (rs1 << rs1_offset) | \
        (rs2 << rs2_offset) | \
        (imm11_5 << imm11_5_offset)

def instruc_btype(opcode: int, funct3: int, rs1: int, rs2: int, imm: int):
    """
    Args:
        opcode: uint8_t
        funct3: uint8_t
        rs1: uint8_t
        rs2: uint8_tm
        imm the lsb should be zero (will be ignored).
    
    Return:
        return uint32_t
    """
    if DO_ASSERT:
        assert(opcode < (1 << 7))
        assert(funct3 < 8)
        assert(rs1 < 32)
        assert(rs2 < 32)
        # assert(imm < (1 << 13))
        # assert(not (imm & 0b1))

        assert(opcode >= 0)
        assert(funct3 >= 0)
        assert(rs1 >= 0)
        assert(rs2 >= 0)
        # assert(imm >= 0)

    imm = imm & 0b1111111111111

    imm4_1_11_offset = 7
    funct3_offset = imm4_1_11_offset + 5
    rs1_offset = funct3_offset + 3
    rs2_offset = rs1_offset + 5
    imm12_10_5_offset = rs2_offset + 5

    imm4_1_11 = ((imm >> 11) & 1) | (((imm >> 1) & 0b1111) << 1)
    imm12_10_5 = ((imm >> 5) & 0b111111) | (((imm >> 12) & 0b1) << 6)

    return opcode | \
        (imm4_1_11 << imm4_1_11_offset) | \
        (funct3 << funct3_offset) | \
        (rs1 << rs1_offset) | \
        (rs2 << rs2_offset) | \
        (imm12_10_5 << imm12_10_5_offset)

def instruc_utype(opcode: int, rd: int, imm: int):
    """
    Args:
        opcode: uint8_t
        rd: uint8_t
    Return:
        uint32_t
    """
    if DO_ASSERT:
        assert(opcode < (1 << 7))
        assert(rd < 32)
        # assert(imm < (1 << 32))

        assert(opcode >= 0)
        assert(rd >= 0)
        # assert(imm >= 0)

    rd_offset = 7
    imm31_12_offset = rd_offset + 5

    imm31_12 = imm & 0b11111111111111111111

    return opcode | \
        rd << rd_offset | \
        imm31_12 << imm31_12_offset

def instruc_jtype(opcode: int, rd: int, imm: int):
    """
    Args:
        opcode: uint8_t
        rd: uint8_t
        imm the lsb should be zero (will be ignored).
    
    Return:
        return uint32_t
    """
    if DO_ASSERT:
        assert(opcode < (1 << 7))
        assert(rd < 32)
        # assert(imm < (1 << 20))

        assert(opcode >= 0)
        assert(rd >= 0)
        # assert(imm < (1 << 21))

    rd_offset = 7
    immparts_offset = rd_offset + 5

    immparts = ((imm >> 12) & 0b11111111) | \
        (((imm >> 11) & 0b1) << 8) | \
        (((imm >> 1) & 0b1111111111) << 9) | \
        (((imm >> 20) & 0b1) << 19)

    return opcode | \
        rd << rd_offset | \
        immparts << immparts_offset



def instruc_r4type(opcode: int, rd: int, funct3: int, rs1: int, rs2: int, rs3: int, funct2: int):
    """
    Args:
        opcode: uint8_t
        rd: uint8_t
        funct3: uint8_t
        rs1: uint8_t
        rs2: uint8_t
        rs3: uint8_t
        funct2: uint8_t
    Return:
        uint32_t
    """
    if DO_ASSERT:
        assert(opcode < (1 << 7))
        assert(rd < 32)
        assert(funct3 < 8)
        assert(rs1 < 32)
        assert(rs2 < 32)
        assert(rs3 < 32)
        assert(funct2 < (1 << 2))

        assert(opcode >= 0)
        assert(rd >= 0)
        assert(funct3 >= 0)
        assert(rs1 >= 0)
        assert(rs2 >= 0)
        assert(rs3 >= 0)
        assert(funct2 >= 0)

    rd_offset     = 7
    funct3_offset = rd_offset + 5
    rs1_offset    = funct3_offset + 3
    rs2_offset    = rs1_offset + 5
    funct2_offset = rs2_offset + 5
    rs3_offset = funct2_offset + 2

    return opcode | \
        (rd << rd_offset) | \
        (funct3 << funct3_offset) | \
        (rs1 << rs1_offset) | \
        (rs2 << rs2_offset) | \
        (funct2 << funct2_offset) | \
        (rs3 << rs3_offset)
