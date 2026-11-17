import re
import json
import os
from functools import lru_cache
from pathlib import Path

from common.path import get_soc_dir

# FPU's support module
FPU_MODULE_PATTERNS = (
    "fpu",
    "recfn",
    "rawfn",
    "fptoint",
    "inttofp",
    "fptofp",
)


def _classify_module(mod_lower):
    """Classify a module name (lowercase) into a microarchitectural category.

    Returns the category string, or None if unclassified.
    The order of checks matters: more specific patterns are tested first
    so that e.g. "amoalu" maps to MEM (not ALU) and "divsqrt" maps to
    FP_DIVSQRT (not FPU).
    """
    # --- MEM subsystem (check before ALU so "amoalu" goes here) ---
    if "dcache" in mod_lower or "hellacache" in mod_lower or "amoalu" in mod_lower:
        return "MEM"

    # --- FP division / square-root (check before FPU) ---
    if "divsqrt" in mod_lower:
        return "FP_DIVSQRT"

    # --- FPU datapath / HardFloat helpers (check before MULDIV) ---
    if any(sub in mod_lower for sub in FPU_MODULE_PATTERNS):
        return "FPU"

    # --- Instruction cache / frontend ---
    if "icache" in mod_lower or "frontend" in mod_lower or "shiftqueue" in mod_lower:
        return "ICACHE"

    # --- TLB / MMU (check before INTERCONNECT so "tlb" is not caught by "tl*") ---
    if mod_lower == "tlb" or mod_lower.startswith("tlb_"):
        # matches TLB, TLB_1, etc. but NOT TLBuffer, TLBroadcast
        return "TLB_MMU"
    if "mmu" in mod_lower or "pmp" in mod_lower:
        return "TLB_MMU"

    # Classify functional units before broad core names and generic queues.
    if "alu" in mod_lower:
        return "ALU"
    if "mul" in mod_lower:
        return "MULDIV"
    if any(sub in mod_lower for sub in ("branch", "tage", "rob", "btb")):
        return "BRANCH"
    if any(sub in mod_lower for sub in ("exception", "trap")):
        return "EXCEPTION"

    # --- Interconnect fabric ---
    if any(sub in mod_lower for sub in ("tlxbar", "tlbuffer", "tlmonitor",
                                         "tlfifofixer", "tlbroadcast",
                                         "axi4", "queue")):
        return "INTERCONNECT"

    # --- Interrupt controllers ---
    if "clint" in mod_lower or "plic" in mod_lower:
        return "INTERRUPT"

    # --- CSR ---
    if "csr" in mod_lower:
        return "CSR"

    # --- Core / tile-level ---
    if any(sub in mod_lower for sub in ("rocket", "boom", "tile", "breakpoint")):
        return "CORE"

    return None


@lru_cache(maxsize=None)
def _coverage_line_categories(source_path):
    """Map source lines to modules once, without writing annotated RTL."""
    categories = [None]  # Verilator line numbers start at one.
    category = None
    with open(source_path) as source:
        for line in source:
            module = re.match(r'^\s*module\s+([a-zA-Z_][a-zA-Z0-9_]*)', line)
            if module:
                category = _classify_module(module.group(1).lower())
                category = {"FP_DIVSQRT": "FPU", "TLB_MMU": "MEM"}.get(category, category)
                categories.append(None)
                continue
            categories.append(category)
            if re.match(r'^\s*endmodule\b', line):
                category = None
    return tuple(categories)


@lru_cache(maxsize=None)
def _coverage_generated_modules(filename, design_name):
    """Locate generated bookkeeping only in a verified coverage source."""
    design_dir = get_soc_dir() / design_name
    marker = f"/soc/{design_name}/"
    candidates = [Path(filename)]
    if marker in filename:
        candidates.append(design_dir / filename.split(marker, 1)[1])
    source_path = next((path for path in candidates if path.is_file()), None)
    if source_path is None:
        return {}
    source_stat = source_path.stat()
    verified = False
    for metadata_path in (design_dir / "build").glob("*/default-verilator/*__verFiles.dat"):
        with open(metadata_path) as metadata:
            for record in metadata:
                match = re.fullmatch(
                    r'S\s+(\d+)\s+\d+\s+\d+\s+\d+\s+(\d+)\s+(\d+)\s+"([^"]+)"\s*',
                    record,
                )
                if (match and match[4] == filename
                        and int(match[1]) == source_stat.st_size
                        and int(match[2]) * 10**9 + int(match[3]) == source_stat.st_mtime_ns):
                    verified = True
                    break
        if verified:
            break
    if not verified:
        return {}

    generated = {}
    module = None
    start = None
    with open(source_path) as source:
        for lineno, line in enumerate(source, 1):
            declaration = re.match(r'^\s*module\s+([a-zA-Z_][a-zA-Z0-9_$]*)', line)
            if declaration:
                if start is not None:
                    return {}
                module = declaration[1]
            begin = re.fullmatch(
                r'\s*// === Ternary Instrumentation for module (\w+) \(\d+ ternaries\) ===\s*', line)
            end = re.fullmatch(r'\s*// === End Instrumentation for module (\w+) ===\s*', line)
            if begin:
                if start is not None or begin[1] != module:
                    return {}
                start = lineno
            if end:
                if start is None or end[1] != module:
                    return {}
                generated.update((point, module) for point in range(start, lineno + 1))
                start = None
            if re.match(r'^\s*endmodule\b', line):
                if start is not None:
                    return {}
                module = None
    return generated if start is None else {}


def compute_category_ratios(merged_path, design_name):
    """Return measured module-category coverage ratios from Verilator data.

    Match annotation counts by combining counters at each source line and
    column, including the extra lines in the ``S`` field. A point is covered
    when its combined count is nonzero, as in ``extract_module_ranges``.
    Prefer module names stored in the coverage records so historical builds
    do not inherit module boundaries from a different local source revision.
    Categories without measured points are omitted. Floating-point division
    belongs to FPU, and translation/protection logic belongs to MEM.
    Exclude explicitly marked generated bookkeeping when retained build
    metadata verifies the source revision and the point's module agrees.
    """
    source_data = {}
    source_categories = {}
    design_dir = get_soc_dir() / design_name
    with open(merged_path) as coverage:
        for record in coverage:
            if not record.startswith("C '"):
                continue
            key, count = record[3:].rsplit("'", 1)
            fields = dict(part.split('\x02', 1) for part in key.split('\x01')
                          if '\x02' in part)
            filename = fields.get('f')
            lineno = int(fields.get('l', 0))
            if not filename or not lineno:
                continue
            generated_modules = _coverage_generated_modules(filename, design_name)
            page_type, _, module = fields.get('page', '').partition('/')
            has_module = (page_type in ('v_line', 'v_branch', 'v_toggle')
                          and re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_$]*', module))
            if has_module:
                category = _classify_module(module.lower())
                category = {"FP_DIVSQRT": "FPU", "TLB_MMU": "MEM"}.get(category, category)
                categories = None
            elif filename not in source_categories:
                # Simulators retain the original build directory after a move.
                marker = f"/soc/{design_name}/"
                relative = filename.split(marker, 1)[-1] if marker in filename else None
                candidates = ([design_dir / relative] if relative else []) + [
                    Path(filename),
                    design_dir / "vsrc" / Path(filename).name,
                    design_dir / "src" / Path(filename).name,
                ]
                source_path = next((path for path in candidates if path.is_file()), None)
                if source_path is None:
                    raise FileNotFoundError(f"Coverage source is missing: {filename}")
                source_categories[filename] = _coverage_line_categories(str(source_path.resolve()))
            if not has_module:
                categories = source_categories[filename]
            points = source_data.setdefault(filename, {})
            column = int(fields.get('n', 0))
            covered = int(count) != 0
            spans = [(lineno, lineno)]
            for span in fields.get('S', '').split(','):
                if span:
                    bounds = span.split('-', 1)
                    spans.append((int(bounds[0]), int(bounds[-1])))
            for start, end in spans:
                for source_line in range(start, end + 1):
                    generated_module = generated_modules.get(source_line)
                    if generated_module and (not has_module or module == generated_module
                                             or module.startswith(generated_module + '__')):
                        continue
                    if categories is not None:
                        if source_line >= len(categories):
                            raise ValueError(f"Coverage line {source_line} exceeds {filename}")
                        category = categories[source_line]
                    if category is not None:
                        point = (source_line, column)
                        points[point] = (category, points.get(point, (category, False))[1] or covered)

    counts = {}
    for points in source_data.values():
        for category, covered in points.values():
            category_counts = counts.setdefault(category, [0, 0])
            category_counts[0] += covered
            category_counts[1] += 1
    return {category: covered / total for category, (covered, total) in counts.items()}


def extract_module_ranges(file_path, output_path):
    categorized_modules = {
        "ALU": [],
        "FPU": [],
        "MULDIV": [],
        "BRANCH": [],
        "EXCEPTION": [],
        "MEM": [],
        "ICACHE": [],
        "TLB_MMU": [],
        "INTERCONNECT": [],
        "CORE": [],
        "INTERRUPT": [],
        "CSR": [],
        "FP_DIVSQRT": [],
    }

    current_module = None
    start_line = None

    module_pattern    = re.compile(r'^\s*module\s+([a-zA-Z_][a-zA-Z0-9_]*)')
    endmodule_pattern = re.compile(r'^\s*endmodule\b')
    cov_point         = re.compile(r'^[ ~%]*([0-9]+)\s+')

    total   = 0
    covered = 0
    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, start=1):
            m = module_pattern.match(line)
            if m:
                current_module = m.group(1)
                start_line = line_num
                continue

            if current_module:
                is_cov_point = cov_point.match(line)
                if is_cov_point:
                    cov_num = int(is_cov_point.group(1))
                    if cov_num != 0:
                        covered += 1
                    total += 1

            if endmodule_pattern.match(line) and current_module:
                mod_lower = current_module.lower()
                category = _classify_module(mod_lower)

                if category is not None and category in categorized_modules:
                    categorized_modules[category].append({
                        "range": f"{start_line}-{line_num}",
                        "module": current_module,
                        "covered": covered,
                        "total": total
                    })

                total = 0
                covered = 0
                current_module = None
                start_line = None

    with open(output_path, 'w') as out:
        json.dump(categorized_modules, out, indent=2)


# ---------------------------------------------------------------------------
# Standalone instruction-category percentage analysis
# ---------------------------------------------------------------------------

def analyze_category_percentages(json_path, output_path=None):
    """Compute per-category coverage statistics from a module_mapping JSON.

    Args:
        json_path:   Path to a module_mapping.json produced by extract_module_ranges().
        output_path: Optional path to write results (CSV).  If None, results are
                     only printed to stdout.

    Returns:
        dict  {category: {"count": int, "total": int, "percentage": float}, ...}
    """
    with open(json_path, "r") as f:
        data = json.load(f)

    grand_total   = 0
    grand_covered = 0
    stats = {}

    for category, modules in data.items():
        cat_covered = sum(m["covered"] for m in modules)
        cat_total   = sum(m["total"]   for m in modules)
        grand_total   += cat_total
        grand_covered += cat_covered
        stats[category] = {
            "covered": cat_covered,
            "total":   cat_total,
            "percentage": 0.0,
        }

    # Compute percentages relative to grand total of coverage points
    if grand_total > 0:
        for cat in stats:
            stats[cat]["percentage"] = round(
                stats[cat]["total"] / grand_total * 100, 2
            )

    # Pretty-print to stdout
    print(f"\n{'Category':<16} {'Covered':>8} {'Total':>8} {'Pct of Total':>13}")
    print("-" * 48)
    for cat in sorted(stats.keys()):
        s = stats[cat]
        print(f"{cat:<16} {s['covered']:>8} {s['total']:>8} {s['percentage']:>12.2f}%")
    print("-" * 48)
    print(f"{'GRAND TOTAL':<16} {grand_covered:>8} {grand_total:>8} {'100.00':>12}%")
    print(f"\nTotal coverage points analyzed: {grand_total}")
    print(f"Total covered:                  {grand_covered}")
    if grand_total > 0:
        print(f"Overall coverage ratio:         {grand_covered/grand_total:.4f}")

    # Optionally write CSV
    if output_path is not None:
        import csv
        with open(output_path, "w", newline="") as csvf:
            writer = csv.writer(csvf)
            writer.writerow(["category", "covered", "total", "pct_of_total"])
            for cat in sorted(stats.keys()):
                s = stats[cat]
                writer.writerow([cat, s["covered"], s["total"], s["percentage"]])
            writer.writerow(["GRAND_TOTAL", grand_covered, grand_total, 100.0])
        print(f"\nResults written to {output_path}")

    return stats


# Allow running as standalone script:
#   python3 -m coverage.CovAnalysis <sv_file> [output.csv]
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 -m coverage.CovAnalysis <annotated.sv> [output.csv]")
        print("       Parses an annotated SystemVerilog file into category percentages.")
        sys.exit(1)

    sv_input   = sys.argv[1]
    tmp_json   = sv_input + ".module_mapping.json"
    csv_output = sys.argv[2] if len(sys.argv) > 2 else None

    extract_module_ranges(sv_input, tmp_json)
    analyze_category_percentages(tmp_json, csv_output)

    # Clean up temp json if no explicit output was requested
    if csv_output is None:
        os.remove(tmp_json)
