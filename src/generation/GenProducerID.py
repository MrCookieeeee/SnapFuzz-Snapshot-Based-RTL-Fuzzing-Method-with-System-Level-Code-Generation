from typing import TYPE_CHECKING
from generation.Instructions import INSTRUCTIONS_BY_ISA_CLASS
from params.runparams import DO_ASSERT

from generation.InstructionsCfClass import MisalignedMemInstruction, GenericCSRWriterInstruction, TvecWriterInstruction, EPCWriterInstruction, PrivilegeDescentInstruction, ExceptionInstruction, is_placeholder
from generation.Instructions import ISAInstrClass
from rv.csrids import CSR_IDS

if TYPE_CHECKING:
    from initialstate.FuzzerState import FuzzerState


def gen_producer_id_to_tgtaddr(fuzzerstate: 'FuzzerState', memop_addrs):
    """
      Two steps. First, generate producer_id_to_tgtaddr. 
                 Then, use it to populate the producers with target addresses. 
      The second step is done in another function.
    """
    # Step 1
    index_in_memaddr_array = 0
    index_in_bb_start_addr_seq = 1 # This variable lets us know to which address we wish to jump when some CF instruction is taken
    producer_id_to_tgtaddr = dict() # producer_id_to_tgtaddr[producer_id] = tgt_addr
    producer_id_to_noreloc_spike = dict() # producer_id_to_noreloc_spike[producer_id] = bool, where bool is true if the value we want to specify should not be relocated for spike

    # To facilitate backward propagation of addresses during exceptions, we recall the tvec writes.
    # When they are consumed, we forget them.
    last_mtvec = None # last_mtvec is a tuple (bb_id, instr_id)
    last_stvec = None # last_stvec is a tuple (bb_id, instr_id)
    last_mepc = None  # last_mepc  is a tuple (bb_id, instr_id)
    last_sepc = None  # last_sepc  is a tuple (bb_id, instr_id)

    for bb_id, bb_instrlist in enumerate(fuzzerstate.instr_objs_seq):
        for bb_instr_id, bb_instr in enumerate(bb_instrlist):

            # ----------------------------------------------------
            # For producer_id_to_noreloc_spike
            # ----------------------------------------------------
            if isinstance(bb_instr, GenericCSRWriterInstruction) and bb_instr.csr_instr.csr_id == CSR_IDS.MEDELEG:
                producer_id_to_noreloc_spike[bb_instr.producer_id] = True

            # ----------------------------------------------------
            # Check for instructions that do not have an instruction string, such as placeholder instructions or some CSR write instructions.
            # ----------------------------------------------------
            if is_placeholder(bb_instr):
                continue
            
            # ----------------------------------------------------
            # To facilitate backward propagation of addresses during exceptions
            # ----------------------------------------------------
            if isinstance(bb_instr, TvecWriterInstruction):
                if bb_instr.is_mtvec:
                    last_mtvec = (bb_id, bb_instr_id)
                else:
                    last_stvec = (bb_id, bb_instr_id)
                continue
            # ----------------------------------------------------
            # To facilitate backward propagation of addresses during trap returns
            # ----------------------------------------------------
            if isinstance(bb_instr, EPCWriterInstruction):
                if bb_instr.is_mepc:
                    last_mepc = (bb_id, bb_instr_id)
                else:
                    last_sepc = (bb_id, bb_instr_id)
                continue

            # ----------------------------------------------------
            # To facilitate backward propagation of addresses during exceptions
            # ----------------------------------------------------
            if isinstance(bb_instr, GenericCSRWriterInstruction):
                if DO_ASSERT:
                    assert bb_instr.producer_id == -1 or not bb_instr.producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)
                producer_id_to_tgtaddr[bb_instr.producer_id] = bb_instr.val_to_write_cpu
                continue

            # ----------------------------------------------------
            # In case of a privilege descent instruction
            # ----------------------------------------------------
            if isinstance(bb_instr, PrivilegeDescentInstruction):
                # Extremely similar to handling exception instruction below
                # Check that a corresponding xepc has been setup
                if DO_ASSERT:
                    assert (bb_instr.is_mret and last_mepc) or (not bb_instr.is_mret and last_sepc), "No epc found for privilege descent instruction. Values are: last_mepc = {}, last_sepc = {}, bb_instr.is_mret = {}".format(last_mepc, last_sepc, bb_instr.is_mret)

                # Get the epc instr's producer id
                if bb_instr.is_mret:
                    epc_producer_id = fuzzerstate.instr_objs_seq[last_mepc[0]][last_mepc[1]].producer_id
                else:
                    epc_producer_id = fuzzerstate.instr_objs_seq[last_sepc[0]][last_sepc[1]].producer_id

                # Get the next bb's start address
                if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                    if DO_ASSERT:
                        assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0
                    addr = fuzzerstate.final_bb_base_addr # Final basic block
                else:
                    addr = fuzzerstate.bb_start_addr_seq[index_in_bb_start_addr_seq]
                    index_in_bb_start_addr_seq += 1
                if DO_ASSERT:
                    assert epc_producer_id > 0

                if DO_ASSERT:
                    assert epc_producer_id == -1 or not epc_producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)
                producer_id_to_tgtaddr[epc_producer_id] = addr
                # Do not use twice the same epc value because we want to jump to a new basic block.
                if bb_instr.is_mret:
                    last_mepc = None
                else:
                    last_sepc = None

            # ---------------------------------------------------------------------------------------------------
            # In case of an exception instruction, find the last corresponding tvec and transmit the target address
            # However, SnapFuzz will handle all the mtvec/stvec by itself, no need to populatr mtvec here 
            # ---------------------------------------------------------------------------------------------------
            if isinstance(bb_instr, ExceptionInstruction):
                continue
                # Check that a corresponding tvec has been setup
                if DO_ASSERT:
                    assert (bb_instr.is_mtvec and last_mtvec) or (not bb_instr.is_mtvec and last_stvec), "No tvec found for exception instruction. Values are: last_mtvec = {}, last_stvec = {}, bb_instr.is_mtvec = {}".format(last_mtvec, last_stvec, bb_instr.is_mtvec)

                # Get the tvec instr's producer id
                if bb_instr.is_mtvec:
                    tvec_producer_id = fuzzerstate.instr_objs_seq[last_mtvec[0]][last_mtvec[1]].producer_id
                else:
                    tvec_producer_id = fuzzerstate.instr_objs_seq[last_stvec[0]][last_stvec[1]].producer_id

                # Get the next bb's start address
                if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                    if DO_ASSERT:
                        assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0
                    addr = fuzzerstate.final_bb_base_addr # Final basic block
                else:
                    addr = fuzzerstate.bb_start_addr_seq[index_in_bb_start_addr_seq]
                    index_in_bb_start_addr_seq += 1
                if DO_ASSERT:
                    assert tvec_producer_id > 0

                if DO_ASSERT:
                    assert tvec_producer_id == -1 or not tvec_producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)
                producer_id_to_tgtaddr[tvec_producer_id] = addr

                # Do not use twice the same tvec value because we want to jump to a new basic block.
                if bb_instr.is_mtvec:
                    last_mtvec = None
                else:
                    last_stvec = None

                # Some exceptions also require their own produced register, not only for tvec but also to make a targeted memory operation
                if bb_instr.producer_id is not None:
                    del addr
                    if isinstance(bb_instr, MisalignedMemInstruction):
                        addr = bb_instr.misaligned_addr
                    else:
                        raise Exception("We expected only MisalignedMemInstruction to have a producer_id.")

                    if DO_ASSERT:
                        assert bb_instr.producer_id == -1 or not bb_instr.producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)
                    producer_id_to_tgtaddr[bb_instr.producer_id] = addr


            # ------------------------------------------------------------------------------------------
            # Check for "traditional" instructions, which have an instruction string.
            # ------------------------------------------------------------------------------------------
            if bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.JALR]:
                # The last JALR instr, jump to final block
                if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                    if DO_ASSERT:
                        assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0
                    addr = fuzzerstate.final_bb_base_addr
                else:
                    addr = fuzzerstate.bb_start_addr_seq[index_in_bb_start_addr_seq]
                    index_in_bb_start_addr_seq += 1
                if DO_ASSERT:
                    assert bb_instr.producer_id > 0
                    assert bb_instr.producer_id == -1 or not bb_instr.producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)
                producer_id_to_tgtaddr[bb_instr.producer_id] = addr

            elif bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEM] or bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEM64] or bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEMFPU] or bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEMFPUD] \
                or bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.AMO] or bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.AMO64]:
                if DO_ASSERT:
                    assert bb_instr.producer_id == -1 or not bb_instr.producer_id in producer_id_to_tgtaddr, "producer_id {} already in producer_id_to_tgtaddr".format(bb_instr.producer_id)
                producer_id_to_tgtaddr[bb_instr.producer_id] = memop_addrs[index_in_memaddr_array]
                # print(f"Mapping producer ID {bb_instr.producer_id} to memory op address {hex(memop_addrs[index_in_memaddr_array])}")
                index_in_memaddr_array += 1

            elif bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.JAL] or (bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.BRANCH] and bb_instr.plan_taken):
                # The last JAL or BRANCH instr, jump to final block
                if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                    if DO_ASSERT:
                        assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0

                    # NOTICE: if the last instr is compressed, fuzzerstate.bb_compressed_count[bb_id] is 1 more for the curr addr
                    curr_addr = fuzzerstate.bb_start_addr_seq[bb_id] + bb_instr_id * 4 - fuzzerstate.bb_compressed_count[bb_id] * 2 + bb_instr.iscompressed * 2 # HAS_COMPRESS

                    bb_instr.imm = fuzzerstate.final_bb_base_addr - curr_addr

                    # There's a special case: the last instr is compressed when generated for next bb
                    #   but right now we need it to jump to final block, and its imm is too large
                    if bb_instr.iscompressed == True:
                        if not -2048 <= bb_instr.imm < 2048:
                            bb_instr.iscompressed = False
                            
                index_in_bb_start_addr_seq += 1

            elif bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.SPECIAL]:
                pass

    if DO_ASSERT:
        index_in_memaddr_array = len(memop_addrs), f"Not all memop addresses were used. Used {index_in_memaddr_array}, but had {len(memop_addrs)}"
    # for key, val in producer_id_to_tgtaddr.items():
    #     print("Producer ID {} -> Target Address {}".format(key, hex(val)))
    return producer_id_to_tgtaddr, producer_id_to_noreloc_spike