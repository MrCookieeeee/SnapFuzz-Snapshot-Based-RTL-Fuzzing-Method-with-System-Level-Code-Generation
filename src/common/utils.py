import random
import enum
import typing
from params.runparams import DO_ASSERT
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from initialstate.FuzzerState import FuzzerState


def li_into_reg(val_unsigned: int, do_check_bounds: bool = True):
    if DO_ASSERT:
        assert val_unsigned >= 0
        if do_check_bounds:
            assert val_unsigned < 0x80000000, f"For the destination address `{hex(val_unsigned)}`, we will need to manage sign extension, which is not yet implemented here."

    # Check whether the MSB of the addi would be 1. In this case, we will add 1 to the lui
    is_sign_extend_ones = (val_unsigned >> 11) & 1

    addi_imm = val_unsigned & 0xFFF
    # Make it negative properly
    if is_sign_extend_ones:
        addi_imm = -((~addi_imm) & 0xFFF) - 1
    lui_imm  = (int(is_sign_extend_ones) + (val_unsigned >> 12)) & 0xFFFFF
    return lui_imm, addi_imm

def li_signed_into_reg(val_signed: int, do_check_bounds: bool = True):
    """
    Generate (lui_imm, addi_imm) for signed immediate values.
    Supports both positive and negative numbers.
    """
    # Convert to 32-bit signed
    assert (-0x80000000 <= val_signed < 0x80000000), f"Immediate {val_signed} out of 32-bit signed range."

    # 对于负数要转换成 unsigned 表示再提取字段
    val_unsigned = val_signed & 0xFFFFFFFF

    # 和原函数一样，但不做非负断言
    is_sign_extend_ones = (val_unsigned >> 11) & 1

    addi_imm = val_unsigned & 0xFFF
    if is_sign_extend_ones:
        addi_imm = -((~addi_imm) & 0xFFF) - 1

    lui_imm = (int(is_sign_extend_ones) + (val_unsigned >> 12)) & 0xFFFFF

    return lui_imm, addi_imm

# From an unsigned int coded on 32 or 64 bits, returns the signed value when interpreting the value as signed
def twos_complement(val_unsigned: int, is_design_64bit: bool):
    if is_design_64bit:
        if DO_ASSERT:
            assert val_unsigned >= 0
            assert val_unsigned < 1 << 64
        return val_unsigned - (((val_unsigned >> 63) & 1) << 64)
    else:
        if DO_ASSERT:
            assert val_unsigned >= 0
            assert val_unsigned < 1 << 32
        return val_unsigned - (((val_unsigned >> 31) & 1) << 32)

# From a signed int, returns an unsigned version.
# This should be a reciprocal function of twos_complement.
def to_unsigned(val_signed: int, is_design_64bit: bool):
    if is_design_64bit:
        if DO_ASSERT:
            assert val_signed < 1 << 63
        return (((val_signed >> 63) & 1) << 64) + val_signed
    else:
        if DO_ASSERT:
            assert val_signed < 1 << 32
        return (((val_signed >> 31) & 1) << 32) + val_signed
    

# Random rounding modes
def gen_random_rounding_mode():
    return random.sample([0, 1, 2, 3, 4, 7], 1)[0]

class ExceptionCauseVal(enum.IntEnum):
    # Important: the values must match the ones in the RISC-V specification, so do not use enum.auto and make sure to skip the reserved values
    ID_INSTR_ADDR_MISALIGNED        = 0
    ID_INSTR_ACCESS_FAULT           = 1
    ID_ILLEGAL_INSTRUCTION          = 2
    ID_BREAKPOINT                   = 3
    ID_LOAD_ADDR_MISALIGNED         = 4
    ID_LOAD_ACCESS_FAULT            = 5
    ID_STORE_AMO_ADDR_MISALIGNED    = 6
    ID_STORE_AMO_ACCESS_FAULT       = 7
    ID_ENVIRONMENT_CALL_FROM_U_MODE = 8
    ID_ENVIRONMENT_CALL_FROM_S_MODE = 9
    ID_ENVIRONMENT_CALL_FROM_M_MODE = 11
    ID_INSTRUCTION_PAGE_FAULT       = 12
    ID_LOAD_PAGE_FAULT              = 13
    ID_STORE_AMO_PAGE_FAULT         = 15


# The state in which each register can be.
class IntRegIndivState(enum.IntEnum):
    FREE               = enum.auto() # FREE because either initial state, or PRODUCED1 and was used by a consumer but is not its output, or FRESH
    PRODUCED0          = enum.auto() # aka "gen"
    PRODUCED1          = enum.auto() # aka "ready"
    CONSUMED           = enum.auto() # aka "applied". Was either PRODUCED1 and directly consumed as input and output of the consumer, or FREE and just output of the consumer.
    UNRELIABLE         = enum.auto() # If offset but not chosen as applied

