import os

from params.runparams import DO_ASSERT, PATH_TO_TMP
from makeelf.elf import *
import os
import subprocess

from initialstate.FuzzerState import FuzzerState
from generation.GenBasicBlocks import gen_basicblocks
from generation.GenFinalBlock import finalblock_spike_resolution

from params.runparams import NO_REMOVE_TMPFILES

from collections import defaultdict



def gen_elf_from_bbs(fuzzerstate: 'FuzzerState', is_spike_resolution, prefixname: str, test_identifier: str, start_addr: int):
    """
    From a fuzzerstate, generates an ELF, may it be for spike resolution or for RTL simulation
    Also integrates the final block and the trap handler
    
    Args:
        instr_objs an iterable (one per basic block) of iterables of CFInstructions or placeholders
        test_identifier typically the random seed, mem size, design name, max number of bbs
    
    Return:
        elf path
    """
    if DO_ASSERT:
        assert len(fuzzerstate.instr_objs_seq) == len(fuzzerstate.bb_start_addr_seq)

    # ---------------------------------------------------------------------------------------------
    # Initial block and Basic blocks
    # has compressed instr
    # ---------------------------------------------------------------------------------------------
    addr_instrs = defaultdict(bytes) # addr_instrs[addr] = single byte
    for bb_start_addr, bb_instrs in zip(fuzzerstate.bb_start_addr_seq, fuzzerstate.instr_objs_seq):
        curr_addr = bb_start_addr
        for instr_id_in_bb, instr_obj in enumerate(bb_instrs):
            if instr_obj.iscompressed:
                curr_bytecode = instr_obj.gen_bytecode_int(is_spike_resolution=is_spike_resolution).to_bytes(2, 'little')
            else:
                curr_bytecode = instr_obj.gen_bytecode_int(is_spike_resolution=is_spike_resolution).to_bytes(4, 'little')            
            
            # populate addr_instrs 1byte by 1byte 
            for curr_byte_id, curr_byte in enumerate(curr_bytecode):
                if DO_ASSERT:
                    assert curr_addr not in addr_instrs, f"Trying to write twice to the same address: {hex(curr_addr)}"
                addr_instrs[curr_addr] = curr_byte
                curr_addr += 1

    # Auxiliary instructions allocated separately from the generated blocks.
    for instr_obj, instr_addr in fuzzerstate.block_tail_instrs:
        bytecode = instr_obj.gen_bytecode_int(is_spike_resolution=is_spike_resolution).to_bytes(4, 'little')
        for byte_offset, byte in enumerate(bytecode):
            addr = instr_addr + byte_offset
            if DO_ASSERT:
                assert 0 <= addr < fuzzerstate.memsize
                assert addr not in addr_instrs, f"Trying to write twice to the same address: {hex(addr)}"
            addr_instrs[addr] = byte

    # ---------------------------------------------------------------------------------------------
    # For the context save/restore block, usually not used in test generation stage
    # ---------------------------------------------------------------------------------------------
    for instr_id_in_bb, instr_obj in enumerate(fuzzerstate.ctxsv_bb):
        if instr_obj is None:
            raise ValueError(f"instrobj is None for ctxsv_bb at index {instr_id_in_bb}")
        curr_bytecode = instr_obj.gen_bytecode_int(is_spike_resolution=is_spike_resolution).to_bytes(4, 'little')
        for curr_byte_id, curr_byte in enumerate(curr_bytecode):
            curr_addr = fuzzerstate.ctxsv_bb_base_addr + 4*instr_id_in_bb + curr_byte_id # NO_COMPRESSED
            if DO_ASSERT:
                assert curr_addr not in addr_instrs, f"Trying to write twice to the same address: {hex(curr_addr)}"
            addr_instrs[curr_addr] = curr_byte

    # ---------------------------------------------------------------------------------------------
    # initial reg data, located after initial block
    # ---------------------------------------------------------------------------------------------
    for reg_data_id, reg_data_doubleword in enumerate(fuzzerstate.initial_reg_data_content):
        curr_bytecode = reg_data_doubleword.to_bytes(8, 'little')
        for curr_byte_id, curr_byte in enumerate(curr_bytecode):
            curr_addr = fuzzerstate.initial_reg_data_addr + 8*reg_data_id + curr_byte_id # doublewords therefore 8
            if DO_ASSERT:
                assert curr_addr not in addr_instrs, f"Trying to write twice to the same address: {hex(curr_addr)}"
            addr_instrs[curr_addr] = curr_byte
    
    # ---------------------------------------------------------------------------------------------
    # Page table data (Sv39 identity mapping)
    # ---------------------------------------------------------------------------------------------
    for pt_offset, pt_value in fuzzerstate.page_table_data.items():
        curr_bytecode = pt_value.to_bytes(8, 'little')
        for curr_byte_id, curr_byte in enumerate(curr_bytecode):
            curr_addr = pt_offset + curr_byte_id
            if DO_ASSERT:
                assert curr_addr not in addr_instrs, f"Trying to write twice to the same address: {hex(curr_addr)}"
            addr_instrs[curr_addr] = curr_byte
    
    # ---------------------------------------------------------------------------------------------
    # First Level trap handler 
    # Here is_spike_resolution must be false, we need non-condition jump
    # Note that we dont have compressed instr here
    # ---------------------------------------------------------------------------------------------
    for instr_id_in_bb, instr_obj in enumerate(fuzzerstate.trap_handler_bb):
        curr_bytecode = instr_obj.gen_bytecode_int(is_spike_resolution=False).to_bytes(4, 'little')
        # write addr byte by byte
        for curr_byte_id, curr_byte in enumerate(curr_bytecode):
            curr_addr = fuzzerstate.trap_handler_bb_base_addr + 4*instr_id_in_bb + curr_byte_id # NO_COMPRESSED
            if DO_ASSERT:
                assert curr_addr not in addr_instrs, f"Trying to write twice to the same address: {hex(curr_addr)}"
            addr_instrs[curr_addr] = curr_byte
    
    # ---------------------------------------------------------------------------------------------
    # Second Level trap handler -- illegal instr
    # Note that we dont have compressed instr here
    # ---------------------------------------------------------------------------------------------
    for instr_id_in_bb, instr_obj in enumerate(fuzzerstate.trap_handler_ill_instr_bb):
        curr_bytecode = instr_obj.gen_bytecode_int(is_spike_resolution=is_spike_resolution).to_bytes(4, 'little')
        # write addr byte by byte
        for curr_byte_id, curr_byte in enumerate(curr_bytecode):
            curr_addr = fuzzerstate.trap_handler_ill_instr_bb_base_addr + 4*instr_id_in_bb + curr_byte_id # NO_COMPRESSED
            if DO_ASSERT:
                assert curr_addr not in addr_instrs, f"Trying to write twice to the same address: {hex(curr_addr)}"
            addr_instrs[curr_addr] = curr_byte

    # ---------------------------------------------------------------------------------------------
    # Final block
    # Note that we dont have compressed instr here
    # ---------------------------------------------------------------------------------------------
    if is_spike_resolution:
        final_block = finalblock_spike_resolution(fuzzerstate)
    else:
        final_block = fuzzerstate.final_bb
    for instr_id_in_bb, instr_obj in enumerate(final_block):
        curr_bytecode = instr_obj.gen_bytecode_int(is_spike_resolution=is_spike_resolution).to_bytes(4, 'little')
        for curr_byte_id, curr_byte in enumerate(curr_bytecode):
            curr_addr = fuzzerstate.final_bb_base_addr + 4*instr_id_in_bb + curr_byte_id # NO_COMPRESSED
            # print(hex(curr_addr))
            if DO_ASSERT:
                assert curr_addr not in addr_instrs, f"Trying to write twice to the same address: {hex(curr_addr)}"
            addr_instrs[curr_addr] = curr_byte

    # ---------------------------------------------------------------------------------------------
    # Random data block, this is for non-taken branched
    # Note that we dont have compressed instr here
    # ---------------------------------------------------------------------------------------------
    for word_id, word_content in enumerate(fuzzerstate.random_block_content4by4bytes):
        curr_bytecode = word_content.to_bytes(4, 'little')
        for curr_byte_id, curr_byte in enumerate(curr_bytecode):
            curr_addr = fuzzerstate.random_data_block_start_addr + 4*word_id + curr_byte_id # NO_COMPRESSED
            if DO_ASSERT:
                assert curr_addr not in addr_instrs, f"Trying to write twice to the same address: {hex(curr_addr)}"
            addr_instrs[curr_addr] = curr_byte

    # Generate a bytes object
    curr_bytearray = bytearray(fuzzerstate.memsize) # Zero-filled
    for curr_addr, curr_byte in addr_instrs.items():
        curr_bytearray[curr_addr] = curr_byte
    curr_bytes = bytes(curr_bytearray)

    elfpath = os.path.join(PATH_TO_TMP, f"{prefixname}{test_identifier}.elf")

    # Generate the ELF object
    gen_elf(curr_bytes, start_addr=fuzzerstate.bb_start_addr_seq[0], section_addr=start_addr, destination_path=elfpath, is_64bit=fuzzerstate.is_design_64bit)
    
            
    if NO_REMOVE_TMPFILES:
        print(f"Generated RTL ELF path:        {elfpath}")

    return elfpath

def gen_elf(inbytes: bytes, start_addr: int, section_addr: int, destination_path: str, is_64bit: bool) -> None:
    if DO_ASSERT:
        assert destination_path

    elf = ELF(e_machine=EM.EM_RISCV, e_data=ELFDATA.ELFDATA2LSB, e_entry=start_addr)

    # Create the section
    SH_FLAGS = 0x6 # Loadable and executable
    section_id = elf.append_section('.text.init', inbytes, start_addr, sh_flags=SH_FLAGS, sh_addralign=4)
    elf.append_segment(section_id, addr=start_addr, p_offset=0xe2) # Very hacky, we hardcode the section offset.
    elf_bytes = bytes(elf) # We first cast to bytes, since casting to bytes has side-effects (such as offset computation) on the ELF object, that are taken into account just before the bytes are generated.

    # Check that the offsets in the program header and in the section header match
    assert len(elf.Elf.Phdr_table) == 1, "Expected only a single program header"
    assert elf.Elf.Phdr_table[0].p_offset == elf.Elf.Shdr_table[-1].sh_offset, "In ELF: offset mismatch between Phdr and Shdr. Maybe the hack with makeelf did not work this time."

    # Finally, write the bytes into the ELF object
    with open(destination_path, 'wb') as f:
        f.write(elf_bytes)

    # Relocate the section
    if section_addr is not None:
        if is_64bit:
            subprocess.run([f"riscv{os.environ['SNAPFUZZ_RISCV_BITWIDTH']}-unknown-elf-objcopy", '--change-section-address', f".text.init={hex(section_addr)}", '-I', 'elf32-littleriscv', '-O', 'elf64-littleriscv', destination_path], check=True)
        else:
            subprocess.run([f"riscv{os.environ['SNAPFUZZ_RISCV_BITWIDTH']}-unknown-elf-objcopy", '--change-section-address', f".text.init={hex(section_addr)}", destination_path], check=True)
    else:
        if is_64bit:
            subprocess.run([f"riscv{os.environ['SNAPFUZZ_RISCV_BITWIDTH']}-unknown-elf-objcopy", '-I', 'elf32-littleriscv', '-O', 'elf64-littleriscv', destination_path], check=True)

    
    
    
    


    
