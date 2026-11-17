from params.runparams import DO_ASSERT

def instruc_crtype(opcode: int, rs2: int, rds1: int, funct4: int):
    """
    Args:
        opcode: uint8_t
        rd: uint8_t
        rs2: uint8_t
        funct4: uint8_t
    
    Return:
        uint16_t
    """
    if DO_ASSERT:
        assert 0 <= opcode < 4,     f"incorrect opcode={opcode} in instruc_crtype (expected 0-3)"
        assert 0 <= rs2    < 32,    f"incorrect rs2={rs2} in instruc_crtype (expected 0-31)"
        assert 0 <= rds1   < 32,    f"incorrect rds1={rds1} in instruc_crtype (expected 0-31)"
        assert 0 <= funct4 < 16,    f"incorrect funct4={funct4} in instruc_crtype (expected 0-15)"

    rs2_offset = 2
    rds1_offset = rs2_offset + 5
    funct4_offset = rds1_offset + 5

    return opcode | (rs2 << rs2_offset) | (rds1 << rds1_offset) | (funct4 << funct4_offset)

def instruc_citype(opcode: int, rds1: int, funct3: int, imm: int):
    """
    Args:
        opcode: uint8_t
        rds: uint8_t
        funct3: uint8_t
        imm: uint8_t
    
    Return:
        uint16_t
    """
    if DO_ASSERT:
        assert 0 <= opcode < 4,     f"incorrect opcode={opcode} in instruc_citype (expected 0-3)"
        assert 0 <= rds1   < 32,    f"incorrect rds1={rds1} in instruc_citype (expected 0-31)"
        assert 0 <= funct3 < 8,     f"incorrect funct3={funct3} in instruc_citype (expected 0-7)"

    imm4_0_offset = 2
    rds1_offset = imm4_0_offset + 5
    imm5_offset = rds1_offset + 5
    funct3_offset = imm5_offset + 1

    # c.addi16sp special case
    if opcode == 0b01 and funct3 == 0b011 and rds1 == 2:
        if DO_ASSERT:
            assert imm % 16 == 0 and -512 <= imm <= 496, f"incorrect imm={imm} in instruc_citype for c.addi16sp (expected multiples of 16 in [-512, 496])"

            i9 = (imm >> 9) & 0x1  # nzimm[9] -> bit 12
            i4 = (imm >> 4) & 0x1  # nzimm[4] -> bit 6
            i6 = (imm >> 6) & 0x1  # nzimm[6] -> bit 5
            i8 = (imm >> 8) & 0x1  # nzimm[8] -> bit 4
            i7 = (imm >> 7) & 0x1  # nzimm[7] -> bit 3
            i5 = (imm >> 5) & 0x1  # nzimm[5] -> bit 2

            imm4_0 = (i4 << 4) | (i6 << 3) | (i8 << 2) | (i7 << 1) | i5 # This goes to imm[4:0] slot (bits 6:2)
            imm5 = i9                                                   # This goes to imm[5] slot (bit 12)

    # WHY the Fxxx rv32c has so freaking special case for addi16sp???
    else:
        imm4_0 = imm & 0x1F
        imm5   = (imm >> 5) & 0x1

    return opcode | (imm4_0 << imm4_0_offset) | (rds1 << rds1_offset) | \
           (imm5 << imm5_offset) | (funct3 << funct3_offset)



def instruc_csstype(opcode: int, rs2: int, funct3: int, imm: int):
    """
    Args: 
        opcode: uint8_t
        funct3: uint8_t
        rs2: uint8_t
    
    Return:
        uint16_t
    """
    if DO_ASSERT:
        assert 0 <= opcode < 4,     f"incorrect opcode={opcode} in instruc_csstype (expected 0-3)"
        assert 0 <= rs2    < 32,    f"incorrect rs2={rs2} in instruc_csstype (expected 0-31)"
        assert 0 <= funct3 < 8,     f"incorrect funct3={funct3} in instruc_csstype (expected 0-7)"
        assert 0 <= imm    < 128,   f"incorrect imm={imm} in instruc_csstype (expected 0-127)"

    rs2_offset = 2
    imm_offset = rs2_offset + 5
    funct3_offset = imm_offset + 6

    return opcode | (rs2 << rs2_offset) | (imm << imm_offset) | (funct3 << funct3_offset)


def instruc_ciwtype(opcode: int, rdprime: int, funct3: int, imm: int):
    """
    Args:
        opcode: uint8_t
        rd: uint8_t
        funct3: uint8_t
    
    Return:
        uint16_t
    """
    rdprime -= 8

    if DO_ASSERT:
        assert 0 <= opcode  < 4,     f"incorrect opcode={opcode} in instruc_ciwtype"
        assert 0 <= rdprime < 8,     f"incorrect rdprime={rdprime} in instruc_ciwtype (expected 0-7)"
        assert 0 <= funct3  < 8,     f"incorrect funct3={funct3} in instruc_ciwtype (expected 0-7)"
        assert imm % 4 == 0 and 0 <= imm <= 1024,   f"incorrect imm={imm} in instruc_ciwtype (expected [4, 256] )"

    rdprime_offset = 2
    funct3_offset = rdprime_offset + 11
    
    imm_5_4 = (imm >> 4) & 0b11     # bits 5:4 -> inst[12:11]
    imm_9_6 = (imm >> 6) & 0b1111   # bits 9:6 -> inst[10:7]
    imm_2   = (imm >> 2) & 0b1      # bits 2   -> inst[6]
    imm_3   = (imm >> 3) & 0b1      # bits 3:2 -> inst[6:5]
    
    return opcode | (rdprime << rdprime_offset) | (imm_3 << 5) | (imm_2 << 6) | (imm_9_6 << 7) | (imm_5_4 << 11) | (funct3 << funct3_offset)


def instruc_cltype(opcode: int, rdprime: int, rs1prime: int, funct3: int, imm: int):
    """
    Args:
        opcode: uint8_t
        rd: uint8_t
        funct3: uint8_t
        rs1: uint8_t
        imm: uint8_t
    
    Return:
        uint16_t
    """
    
    # we generate higher than 8 reg, but for encoding, we have to minus 8
    rdprime -= 8
    rs1prime  -= 8

    if DO_ASSERT:
        assert 0 <= opcode   < 4,    f"incorrect opcode={opcode} in instruc_cltype"
        assert 0 <= rdprime  < 8,    f"incorrect rdprime={rdprime} in instruc_cltype"
        assert 0 <= rs1prime < 8,    f"incorrect rs1prime={rs1prime} in instruc_cltype"
        assert 0 <= funct3   < 8,    f"incorrect funct3={funct3} in instruc_cltype"
        assert 0 <= imm      < 32,   f"incorrect imm={imm} in instruc_cltype (expected 0-31)"

    rdprime_offset = 2
    imm1_0_offset = rdprime_offset + 3
    rs1prime_offset = imm1_0_offset + 2
    imm4_2_offset = rs1prime_offset + 3
    funct3_offset = imm4_2_offset + 3

    imm1_0 = imm & 0x3
    imm4_2 = (imm >> 2) & 0x7

    return opcode | (rdprime << rdprime_offset) | (imm1_0 << imm1_0_offset) | \
           (rs1prime << rs1prime_offset) | (imm4_2 << imm4_2_offset) | (funct3 << funct3_offset)

def instruc_cstype(opcode: int, rs2prime: int, rs1prime: int, funct3: int, imm: int):
    """
    Args:
        opcode: uint8_t
        funct3: uint8_t
        rs1: uint8_t
        rs2: uint8_t
        imm: uint8_t

    Return:
        uint16_t
    """
    # we generate higher than 8 reg, but for encoding, we have to minus 8
    rs1prime -= 8
    rs2prime -= 8

    if DO_ASSERT:
        assert 0 <= opcode   <  4,    f"incorrect opcode={opcode} in instruc_cstype"
        assert 0 <= rs1prime <  8,    f"incorrect rs1prime={rs1prime} in instruc_cstype"
        assert 0 <= rs2prime <  8,    f"incorrect rs2prime={rs2prime} in instruc_cstype"
        assert 0 <= funct3   <  8,    f"incorrect funct3={funct3} in instruc_cstype"
        assert 0 <= imm      < 32,    f"incorrect imm={imm} in instruc_cstype"

    rs2prime_offset = 2
    imm2_offset     = rs2prime_offset + 3
    rs1prime_offset = imm2_offset + 2
    imm3_offset     = rs1prime_offset + 3
    funct3_offset   = imm3_offset + 3

    # 2 bits imm and 3 bits imm
    imm2 = imm & 0x3
    imm3 = (imm >> 2) & 0x7

    return opcode | (rs2prime << rs2prime_offset) | (imm2 << imm2_offset) | \
           (rs1prime << rs1prime_offset) | (imm3 << imm3_offset) | (funct3 << funct3_offset)


def instruc_catype(opcode: int, rs2prime: int, funct2: int, rds1prime: int, funct6: int):
    """
    Args:
        opcode: uint8_t
        rd: uint8_t
        rs2: uint8_t
        funct2: uint8_t
        funct6: uint8_t
    
    Return:
        uint16_t
    """

    # we generate higher than 8 reg, but for encoding, we have to minus 8
    rds1prime -= 8
    rs2prime  -= 8

    if DO_ASSERT:
        assert 0 <= opcode    < 4,     f"incorrect opcode={opcode} in instruc_catype"
        assert 0 <= rs2prime  < 8,     f"incorrect rs2prime={rs2prime} in instruc_catype"
        assert 0 <= funct2    < 4,     f"incorrect funct2={funct2} in instruc_catype (expected 0-3)"
        assert 0 <= rds1prime < 8,     f"incorrect rds1prime={rds1prime} in instruc_catype"
        assert 0 <= funct6    < 64,    f"incorrect funct6={funct6} in instruc_catype (expected 0-63)"

    rs2prime_offset = 2
    funct2_offset = rs2prime_offset + 3
    rds1prime_offset = funct2_offset + 2
    funct6_offset = rds1prime_offset + 3

    return opcode | (rs2prime << rs2prime_offset) | (funct2 << funct2_offset) | \
           (rds1prime << rds1prime_offset) | (funct6 << funct6_offset)

def instruc_cbtype(opcode: int, rds1prime: int, funct3: int, imm: int):
    """
    Args:
        opcode: uint8_t
        funct3: uint8_t
        rs1: uint8_t
        imm: uint8_t

    Return: 
        uint16_t
    """
    if DO_ASSERT:
        assert 0 <= opcode    < 4,      f"incorrect opcode={opcode} in instruc_cbtype"
        assert 0 <= rds1prime < 8,      f"incorrect rds1prime={rds1prime} in instruc_cbtype"
        assert 0 <= funct3    < 8,      f"incorrect funct3={funct3} in instruc_cbtype"
        # imm is large; normally signed. No strict bound.

    imm4_0_offset = 2
    rds1prime_offset = imm4_0_offset + 5
    imm7_5_offset = rds1prime_offset + 3
    funct3_offset = imm7_5_offset + 3

    imm4_0 = imm & 0x1F
    imm7_5 = (imm >> 5) & 0x7

    return opcode | (imm4_0 << imm4_0_offset) | (rds1prime << rds1prime_offset) | \
           (imm7_5 << imm7_5_offset) | (funct3 << funct3_offset)

def instruc_cbtype_shift_andi(opcode: int, rds1prime: int, funct2: int, funct3: int, imm: int):
    """
    Encode CB-type instructions: C.SRLI, C.SRAI, C.ANDI

    Args:
        opcode:   bottom 2 bits (C1 quadrant → usually 0b01 = 1)
        rds1prime: compressed reg index 0-7  (maps to x8-x15)
        imm:      shift amount or sign-immediate

    Return:
        uint16_t encoding
    """
    rds1prime -= 8

    if DO_ASSERT:
        assert 0   <= opcode    < 4,      f"incorrect opcode={opcode} in instruc_cbtype_shift_andi"
        assert 0   <= rds1prime < 8,      f"incorrect rds1prime={rds1prime} in instruc_cbtype_shift_andi"
        assert 0   <= funct2    < 4,      f"incorrect funct2={funct2} in instruc_cbtype_shift_andi (expected 0-3)"
        assert 0   <= funct3    < 8,      f"incorrect funct3={funct3} in instruc_cbtype_shift_andi"
        assert -32 <= imm       < 32,     f"incorrect imm={imm} in instruc_cbtype_shift_andi (expected [-32, 32))"

    # Immediate split (shared encoding)
    imm4_0 = imm & 0x1F      # low 5 bits
    imm5   = (imm >> 5) & 1  # bit 5 is funct2 extension

    imm4_0_offset = 2
    rds1prime_offset = imm4_0_offset + 5
    funct2_offset = rds1prime_offset + 3
    imm5_offset = funct2_offset + 2
    funct3_offset = imm5_offset + 1

    return (opcode) | (imm4_0 << imm4_0_offset) | (rds1prime << rds1prime_offset) | (funct2 << funct2_offset) | (imm5 << imm5_offset) | (funct3 << funct3_offset)

def instruc_cjtype(opcode: int, funct3: int, imm: int):
    """
    Args:
        opcode: uint8_t
        funct3: uint8_t

    Return:
        uint16_t
    """
    if DO_ASSERT:
        assert imm % 2 == 0, f"incorrect imm={imm} in instruc_cjtype (expected even number)"
    
    if DO_ASSERT:
        assert 0     <= opcode < 4,     f"incorrect opcode={opcode} in instruc_cjtype"
        assert 0     <= funct3 < 8,     f"incorrect funct3={funct3} in instruc_cjtype"
        assert -2048 <= imm < 2048,     f"incorrect imm={imm} in instruc_cjtype (expected [-1024, 1024))"

    # imm it self can be [-2048, 2048), which is ±2 KiB range, refer to spec
    # special case: -100/2 = -50.0, / produce float, so we use //
    imm = imm // 2
    imm &= 0x7FF   

    imm_offset = 2
    funct3_offset = imm_offset + 11

    # Extract CJ immediate bits (spec order: [11|4|9:8|10|6|7|3:1|5])
    # Fxxx the stupid order!!!
    i11 = (imm >> 10) & 0x1   # offset[11] -> bit 11
    i4  = (imm >> 3)  & 0x1   # offset[4]  -> bit 10
    i9  = (imm >> 8)  & 0x1   # offset[9]  -> bit 9
    i8  = (imm >> 7)  & 0x1   # offset[8]  -> bit 8
    i10 = (imm >> 9)  & 0x1   # offset[10] -> bit 7
    i6  = (imm >> 5)  & 0x1   # offset[6]  -> bit 6
    i7  = (imm >> 6)  & 0x1   # offset[7]  -> bit 5
    i3  = (imm >> 2)  & 0x1   # offset[3]  -> bit 4
    i2  = (imm >> 1)  & 0x1   # offset[2]  -> bit 3
    i1  = (imm >> 0)  & 0x1   # offset[1]  -> bit 2
    i5  = (imm >> 4)  & 0x1   # offset[5]  -> bit 1

    imm_enc = (
        (i11 << 10) |
        (i4  << 9)  |
        (i9  << 8)  |
        (i8  << 7)  |
        (i10 << 6)  |
        (i6  << 5)  |
        (i7  << 4)  |
        (i3  << 3)  |
        (i2  << 2)  |
        (i1  << 1)  |
        (i5  << 0)
    )

    return opcode | (imm_enc << imm_offset) | (funct3 << funct3_offset)
