import json
import os
from functools import cache

from common.path import get_design_cfg_path


SUPPORTED_DESIGNS = ("boom", "rocket", "xiangshan")


@cache
def get_design_cfg(design_name):
    if design_name not in SUPPORTED_DESIGNS:
        raise ValueError(f"Unsupported design `{design_name}`. Supported designs: {', '.join(SUPPORTED_DESIGNS)}")
    with open(get_design_cfg_path(design_name), "r") as f:
        return json.load(f)

# @param design_name: must be one of the keys of the design_repos.json dict.
# @return the top soc name, for example top_tiny_soc.
def get_design_top_soc(design_name) -> str:
    device_config = get_design_cfg(design_name)
    return device_config["toplevel"]

# @param design_name: must be one of the keys of the design_repos.json dict.
# @return the boot address of the design.
def get_design_boot_addr(design_name) -> int:
    device_config = get_design_cfg(design_name)
    return int(device_config["bootaddr"], base=0)

# @param design_name: must be one of the keys of the design_repos.json dict.
# @return the march flags for the design, for example `-march=rv64gc -mabi=lp64`.
def get_design_march_ccflags(design_name) -> int:
    device_config = get_design_cfg(design_name)
    return device_config["marchflags"]

# @param design_name: must be one of the keys of the design_repos.json dict.
# @return for example `rv64gc`.
def get_design_march_flags(design_name) -> str:
    return get_design_march_ccflags(design_name).split('-march=')[1].split(' ')[0].lower()

def get_design_march_flags_nocompressed(design_name) -> str:
    return get_design_march_ccflags(design_name).split('-march=')[1].split(' ')[0].lower()

# @param design_name: must be one of the keys of the design_repos.json dict.
# @return the stop signal address of the design: the address to which to write to stop the simulation.
def get_design_stop_sig_addr(design_name) -> int:
    device_config = get_design_cfg(design_name)
    return int(device_config["stopsigaddr"], base=0)

# @param design_name: must be one of the keys of the design_repos.json dict.
# @return the register dump address of the design: the address to which the CPU dumps the registers, in order from 1.
def get_design_reg_dump_addr(design_name) -> int:
    device_config = get_design_cfg(design_name)
    return int(device_config["regdumpaddr"], base=0)

# @param design_name: must be one of the keys of the design_repos.json dict.
# @return the floating point register dump address of the design: the address to which the CPU dumps the floating point registers, in order from 0.
def get_design_fpreg_dump_addr(design_name) -> int:
    device_config = get_design_cfg(design_name)
    return int(device_config["fpregdumpaddr"], base=0)

# @param design_name: must be one of the keys of the design_repos.json dict.
# @return true iff the design is 32bit.
@cache
def is_design_32bit(design_name) -> bool:
    march_flags = get_design_march_flags(design_name)
    assert '128' not in march_flags, "Ensure that you support 128-bit design everywhere, and then remove this assertion."
    return '32' in march_flags

#
# InstrTypeSupport 
#
@cache
def design_has_compressed_support(design_name) -> bool:
    config = get_design_cfg(design_name)
    return 'c' in config["InstrTypeSupport"]

@cache
def design_has_float_support(design_name) -> bool:
    config = get_design_cfg(design_name)
    return 'f' in config["InstrTypeSupport"] or 'g' in config["InstrTypeSupport"]

@cache
def design_has_double_support(design_name) -> bool:
    config = get_design_cfg(design_name)
    return 'f' in config["InstrTypeSupport"] or 'g' in config["InstrTypeSupport"]

@cache
def design_has_muldiv_support(design_name) -> bool:
    config = get_design_cfg(design_name)
    return 'm' in config["InstrTypeSupport"] or 'g' in config["InstrTypeSupport"]

@cache
def design_has_atop_support(design_name) -> bool:
    config = get_design_cfg(design_name)
    return 'a' in config["InstrTypeSupport"] or 'g' in config["InstrTypeSupport"]

@cache
def design_has_compressed_support(design_name) -> bool:
    config = get_design_cfg(design_name)
    return 'c' in config["InstrTypeSupport"]

def design_has_misaligned_data_support(design_name) -> bool:
    device_config = get_design_cfg(design_name)
    return device_config["misaligned_data_supported"]


#
# privlvs
#
def design_has_supervisor_mode(design_name) -> str:
    device_config = get_design_cfg(design_name)
    return 's' in device_config["privlvs"]
def design_has_user_mode(design_name) -> str:
    device_config = get_design_cfg(design_name)
    return 'u' in device_config["privlvs"]


#
# pmp physical memory protection
#
def design_has_pmp(design_name) -> bool:
    get_design_cfg(design_name)
    return True


