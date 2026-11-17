# SnapFuzz

Artifact for **SnapFuzz: Snapshot-Based RTL Fuzzing Method with System-Level Code Generation**, ICCD 2026.

SnapFuzz generates RISC-V programs and uses snapshots of RTL statement coverage to adjust instruction-generation probabilities toward underexplored processor components. Its system-level code generation includes privilege transitions, exception-triggering instructions, and embedded trap handlers. For BOOM and Rocket, generated programs run against Spike and RTL simulation for differential checking, with line, branch, and condition coverage collected during fuzzing.

## BOOM and Rocket revisions

| Component | Commit |
| --- | --- |
| [BOOM](https://github.com/riscv-boom/riscv-boom) | [`fac2c370c9deae97ca52aca6b34857e9ac0f6e9d`](https://github.com/riscv-boom/riscv-boom/commit/fac2c370c9deae97ca52aca6b34857e9ac0f6e9d) |
| [Rocket Chip](https://github.com/chipsalliance/rocket-chip) | [`44b0b8249279d25bd75ea693b725d9ff1b96e2ab`](https://github.com/chipsalliance/rocket-chip/commit/44b0b8249279d25bd75ea693b725d9ff1b96e2ab) |

- Linux and Python 3.13. `requirement.txt` contains the external Python dependency, NumPy 2.2.4. The `makeelf` source is bundled in `src/makeelf/`.
- **Verilator 5.006**, including the matching `verilator_coverage` executable, for the artifact's RTL simulation and native line-coverage workflow.
- Spike (`spike`) for the RISC-V reference model.
- RISC-V GNU tools, including `riscv64-unknown-elf-objcopy` and `riscv64-unknown-elf-objdump`.
- The instrumented BOOM/Rocket simulators and their matching RTL sources.
- [VeriFlatten](https://github.com/MrWater98/VeriFlatten) as the external RTL-processing reference for the condition/branch coverage flow.

Obtain the VeriFlatten source as a separate checkout alongside SnapFuzz:

```bash
git clone https://github.com/MrWater98/VeriFlatten.git ../VeriFlatten
```

## Xiangshan revisions
The XiangShan backend requires its own binary file, executable and nemu reference library. Please refer to [`Xiangshan`](https://github.com/OpenXiangShan/XiangShan)

## Coverage instrumentation

| Metric | Instrumentation and collection |
| --- | --- |
| Line coverage | Verilator's built-in line coverage, enabled with `--coverage-line`; native records are merged and summarized with `verilator_coverage`|
| Condition coverage | Explicit RTL coverage instrumentation in the VeriFlatten-based flow; the simulator exposes `cond_cov<N>` bitmaps. |
| Branch coverage | Explicit RTL coverage instrumentation in the VeriFlatten-based flow; the simulator exposes `br_cov<N>` bitmaps. |

Generated RTL often expresses decisions with `?:`. The supplied script retains the original assignment and adds a combinational `if/else` probe before the enclosing module's `endmodule`, making the decision explicit for subsequent coverage instrumentation.
```bash
python3 preprocessing/instrument_ternary.py input.sv output.sv
```

For example, this assignment:

```systemverilog
wire [7:0] result = select ? a : b;
```

is retained, and the following probe is added:

```systemverilog
reg result_tern_0 = 1'b0;
always @(*) begin
  if (select) begin
    result_tern_0 = 1'b1;
  end else begin
    result_tern_0 = 1'b0;
  end
end
```

 The SnapFuzz line-coverage harness must print native coverage records after its `Elapsed time:` line. `src/run_verilator.py` extracts those records, merges them with `verilator_coverage -write`, and reads the total coverage summary.

`src/coverage/CovState.py` parses these signals and combines results across programs with bitwise OR. Both metrics are collected from the branch/condition simulator. Module-level line-coverage snapshots feed the instruction-weight updates in `src/coverage/CoverageYieldRebalancer.py`.

## Simulator integration

Prepare two simulators per DUT: one with native line coverage and one with the VeriFlatten-based condition/branch instrumentation. Place the executables at the paths used by `src/common/path.py`:

| DUT | Line-coverage executable | Condition/branch executable |
| --- | --- | --- |
| BOOM | `soc/Vboom_line_soc` | `soc/Vboom_br_soc` |
| Rocket | `soc/Vrocket_line_soc` | `soc/Vrocket_br_soc` |

The harness must accept `SIMSRAMELF`, `SIMROMELF`, and `SIMLEN`, report `Found a stop request.` on completion, and emit the register dumps consumed by `src/run_verilator.py`. Coverage output must follow the formats above. The design configurations specify the boot address, register-dump addresses, and stop address.

## Setup and execution

Create a Conda environment, install the Python dependency, and activate SnapFuzz:

```bash
conda create --name SnapFuzz --channel conda-forge python=3.13 pip
conda activate SnapFuzz
python -m pip install -r requirement.txt
source env.sh
```

Generate BOOM ELFs:

```bash
python3 src/do_fuzz_design.py boom
```

Or generate Rocket ELFs:

```bash
python3 src/do_fuzz_design.py rocket
```

Generation-only mode is enabled by default and saves final ELFs in `data/`. It retains Spike resolution and requires Spike and RISC-V binutils. It skips RTL profiling, warmup, execution, and coverage updates, using Spike's supported exception-delegation mask during generation.

To execute the generated programs on RTL and collect coverage, install the simulators and Verilator 5.006, then run:

```bash
python3 src/do_fuzz_design.py boom --generate-only False
```

The interface is:

```text
python3 src/do_fuzz_design.py <design_name> [<tolerate_some_bug>] [--no-update] [--generate-only [True|False]]
```

| Argument | Behavior |
| --- | --- |
| `design_name` | `boom`, `rocket`, or the separately integrated `xiangshan` backend. |
| `tolerate_some_bug` | Optional integer, default `0`. A nonzero value activates the existing BOOM/Rocket bug-tolerance helper; `0` leaves the source defaults unchanged. |
| `--generate-only` | Optional `True`/`False` value, default `True`. Use `True` to generate ELFs with Spike resolution, or `False` to enable RTL execution, differential checking, and coverage collection. |
| `--no-update` | Disables coverage-guided instruction-weight updates while retaining BOOM/Rocket coverage collection. |

For a run with instruction-weight updates disabled:

```bash
python3 src/do_fuzz_design.py boom --generate-only False --no-update
```

The entry point currently uses **16 worker processes**, starts its seed counter at **0**, and enables privileged instruction generation. 

## Citation

```bibtex
@inproceedings{qu2026snapfuzz,
  author    = {Zhi Qu and Ziyue Zheng and Yangdi Lyu},
  title     = {{SnapFuzz}: Snapshot-Based {RTL} Fuzzing Method with System-Level Code Generation},
  booktitle = {IEEE International Conference on Computer Design (ICCD)},
  year      = {2026}
}
```
