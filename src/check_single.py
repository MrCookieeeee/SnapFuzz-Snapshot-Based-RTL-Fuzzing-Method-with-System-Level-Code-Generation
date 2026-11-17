from fuzzer import gen_testcases
from common.Spike import calibrate_spikespeed
from common.ProfileDesign import profile_get_medeleg_mask
from common.path import (get_merged_br_cov_path, get_riscv_dv_elfs_dir,
                         get_riscv_dv_xiangshan_elfs_dir, get_root_path,
                         get_xiangshan_emu_path, get_xiangshan_nemu_path)
from run_verilator import runtest_verilator_br_cov_elfs, runsim_verilator_for_elf_lists
from coverage.CovState import CovState
import subprocess
import random
import sys
import os
import time

# Don't delete, for coverage checking
cov_datas = []


def CheckSingle():

    # design_name = 'boom'
    design_name = 'boom'
    descriptor = (
                512445,         # memsize 
                design_name,    # design name
                3,              # randseed
                91,             # max bbs
                1)              # authorize_privileges

    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)

    br_cov_data, line_cov_data = gen_testcases(*descriptor)

    elf_path = get_root_path() / "data" / f"rtl{'_'.join(map(str, descriptor[:4]))}.elf"
    with open(get_root_path() / "elf.txt", "w") as elf_dump:
        subprocess.run(["riscv64-unknown-elf-objdump", "-d", str(elf_path)], stdout=elf_dump, check=True)

    coverage_datas = []
    cov_state = CovState()
    coverage_datas.append(br_cov_data)

    cov_state.merge_coverage_data(coverage_datas, line_cov_data)
    CovState.compute_coverage(cov_state, None)

def set_first_cov(cov_state: CovState):
    global cov_datas
    print("Start Cov:")
    with open(str(get_merged_br_cov_path("boom")), "r") as f:
        cov_data_in_str  = f.readline()
        cov_data_in_dict = eval(cov_data_in_str)

        cov_datas.append(cov_data_in_dict)
        
        line_cov_tmp = "1/1"
        cov_state.merge_coverage_data(cov_datas, line_cov_tmp)
        cov_state.compute_coverage(start_time=None)

        cov_datas = []


def Check_single_file_cov():
    cov_state = CovState()
    set_first_cov(cov_state)

    design_name = "boom"

    # elf_path = Gen_More_Elfs(design_name)
    # elf_path = str(get_riscv_dv_elfs_dir() / "riscv_rand_instr_test_100.elf")
    elf_path = str(get_root_path() / "single.elf")

    coverage_data = runtest_verilator_br_cov_elfs(design_name, elf_path)
    cov_data_in_dict = eval(coverage_data)

    cov_datas.append(cov_data_in_dict)

    line_cov_tmp = "1/1"
    cov_state.merge_coverage_data(cov_datas, line_cov_tmp)

    print("end_cov")
    cov_state.compute_coverage(start_time=None)



def FuzzFileList(design_name, isdebug):
    cov_state = CovState()
    set_first_cov(cov_state)

    directory_path = str(get_root_path() / "riscv_dv_elfs")
    
    start_time      = time.time()
    last_clean_time = time.time()
    elf_files = [f for f in os.listdir(directory_path) if f.endswith(".elf")]
    
    for elf_file in elf_files:        

        # for debug
        if isdebug:
            run_successful, coverage_data = runsim_verilator_for_elf_lists(design_name, str(get_root_path() / 'output.elf'))
            cov_datas = []
            cov_datas.append(coverage_data)
            cov_state.merge_coverage_data(cov_datas)
            cov_state.compute_coverage(start_time)
            cov_datas.clear()  
            last_clean_time = time.time()
            exit()

        # when run directory
        run_successful, coverage_data = runsim_verilator_for_elf_lists(design_name, os.path.join(directory_path, elf_file))
        
        if not run_successful:
            print("fuck the elf")
            exit()
        else:
            print(f"successfuly run {elf_file}")
        
        cov_datas = []
        cov_datas.append(coverage_data)

        if time.time() - last_clean_time > 15:
            cov_state.merge_coverage_data(cov_datas)
            cov_state.compute_coverage(start_time)
            cov_datas.clear()  
            last_clean_time = time.time()


def FuzzFileList_xiangshan():
    directory_path = str(get_riscv_dv_xiangshan_elfs_dir())
    elf_files = [f for f in os.listdir(directory_path) if f.endswith(".elf")]
    for elf_file in elf_files:        
        print(elf_file)
        subprocess.run([f"{get_xiangshan_emu_path()} -i {os.path.join(directory_path, elf_file)} --diff={get_xiangshan_nemu_path()}"], shell=True, check=True)
        print(f"successfully run elf {elf_file}")
        

# ------------------------------------------------------------------------
# Usage:
# python3 CheckSingle.py                    -->  CheckSingle 
# python3 CheckSingle.py xiangshan          -->  FuzzFileList_xiangshan
# python3 CheckSingle.py cov                -->  Check the coverage of file
# python3 CheckSingle.py rocket/boom 1/0    -->  Debug/NoDebug mode FuzzFileList
# ------------------------------------------------------------------------
if __name__ == '__main__':
    if len(sys.argv) == 1:  
        CheckSingle()
    elif sys.argv[1] == "xiangshan":
        FuzzFileList_xiangshan()
    elif sys.argv[1] == "cov":
        Check_single_file_cov()
    else:
        FuzzFileList(sys.argv[1], sys.argv[2])
