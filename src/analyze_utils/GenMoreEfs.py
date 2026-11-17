import random
from initialstate.FuzzerState import FuzzerState
from generation.GenBasicBlocks import gen_basicblocks
from generation.SpikeResolution import spike_resolution
from generation.GenElf import gen_elf_from_bbs
from common.GetCfgs import get_design_boot_addr
from fuzzer import gen_new_test_instance
from common.Spike import calibrate_spikespeed
from common.ProfileDesign import profile_get_medeleg_mask


def _Gen_More_Elfs_(memsize: int, 
                    design_name: str, 
                    randseed: int,
                    nmax_bbs: int, 
                    authorize_privileges: bool, 
                    max_num_instructions: int = None, 
                    no_dependency_bias: bool = False,
                    check_pc_spike_again: bool = False   # TODO actually not initialize as False
                    ):
    
    random.seed(randseed) 
    fuzzerstate = FuzzerState(design_name, 
                              get_design_boot_addr(design_name), 
                              memsize, 
                              randseed,
                              nmax_bbs, 
                              authorize_privileges, 
                              max_num_instructions, 
                              no_dependency_bias)
    gen_basicblocks(fuzzerstate)

    expected_regvals = spike_resolution(fuzzerstate, check_pc_spike_again)
    rtl_elfpath = gen_elf_from_bbs(fuzzerstate, False, 'rtl', fuzzerstate.instance_to_str(), fuzzerstate.design_base_addr)

    print(f"Successfully gen elf: {rtl_elfpath}")
    return rtl_elfpath


def Gen_More_Elfs(design_name):
    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)

    process_instance_id = 1
    memsize, _, _, num_bbs, authorize_privileges = gen_new_test_instance(design_name, process_instance_id, False)
    elf_path = _Gen_More_Elfs_(memsize, design_name, process_instance_id, num_bbs, False, None, True)
    return elf_path