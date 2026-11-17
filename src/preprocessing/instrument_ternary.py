#!/usr/bin/env python3
"""
Instrument ternary operators in SystemVerilog files for coverage analysis.

Usage:
    python3 instrument_ternary.py <input.sv> [output.sv]

For each ternary assignment (in wire or assign statements) of the form:
    wire [63:0] _shout_T_3 = _shin_T_2 ? shout_r : 64'h0;

This script:
1. Keeps the original RTL behavior unchanged (does not break compilation).
2. Adds an if/else instrumentation block that makes the ternary decision
   explicit, for coverage / analysis only.
3. Inserts all instrumentation blocks before each module's ``endmodule``.
   Every module is treated separately.
"""

import re
import sys
import os


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_ternary_question(expr):
    """Return the index of the top-level '?' in *expr*, or -1."""
    depth = 0
    for i, ch in enumerate(expr):
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        elif ch == '?' and depth == 0:
            return i
    return -1


def _find_ternary_colon(expr):
    """Return the index of the top-level ':' in *expr*, or -1.

    This is the colon that pairs with the ternary '?'.
    """
    depth = 0
    for i, ch in enumerate(expr):
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        elif ch == ':' and depth == 0:
            return i
    return -1


def _strip_comment(text):
    """Remove a trailing ``// …`` comment from *text*."""
    # Naive but sufficient for machine-generated SV.
    m = re.search(r'\s*//.*$', text)
    return text[:m.start()] if m else text


def parse_ternary(stmt):
    """Parse a wire/assign statement that may contain a ternary operator.

    Returns a dict with keys
        signal_name, condition, true_val, false_val
    or *None* if the statement does not contain a ternary.
    """
    s = stmt.strip()

    # Skip pure comments
    if s.startswith('//'):
        return None

    # Remove inline comment for parsing
    s = _strip_comment(s)

    # Remove trailing semicolon
    if s.endswith(';'):
        s = s[:-1].strip()

    # --- Match wire declaration ------------------------------------------
    # wire [W:0] name = RHS
    # wire       name = RHS
    wire_m = re.match(r'wire\s+(\[.*?\]\s+)?(\w+)\s*=\s*(.+)', s)

    # --- Match assign statement ------------------------------------------
    # assign name       = RHS
    # assign name[bits] = RHS
    assign_m = re.match(r'assign\s+(\w+)(\s*\[.*?\])?\s*=\s*(.+)', s)

    if wire_m:
        signal_name = wire_m.group(2)
        rhs = wire_m.group(3)
    elif assign_m:
        signal_name = assign_m.group(1)
        rhs = assign_m.group(3)
    else:
        return None

    # Look for a top-level '?'
    q_idx = _find_ternary_question(rhs)
    if q_idx == -1:
        return None

    condition = rhs[:q_idx].strip()
    after_q = rhs[q_idx + 1:]

    colon_idx = _find_ternary_colon(after_q)
    if colon_idx == -1:
        return None

    true_val = after_q[:colon_idx].strip()
    false_val = after_q[colon_idx + 1:].strip()

    return {
        'signal_name': signal_name,
        'condition': condition,
        'true_val': true_val,
        'false_val': false_val,
    }


# ---------------------------------------------------------------------------
# Instrumentation generation
# ---------------------------------------------------------------------------

def generate_instrumentation(ternary_info, index):
    """Return a list of SV lines that instrument one ternary decision."""
    name = ternary_info['signal_name']
    cond = ternary_info['condition']

    cov_reg = f"{name}_tern_{index}"

    return [
        f"  // Ternary instrumentation for {name}",
        f"  reg {cov_reg} = 1'b0;",
        f"  always @(*) begin",
        f"    if ({cond}) begin",
        f"      {cov_reg} = 1'b1;",
        f"    end else begin",
        f"      {cov_reg} = 1'b0;",
        f"    end",
        f"  end",
    ]


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------

def instrument_file(input_path, output_path):
    """Read *input_path*, instrument ternary operators, write *output_path*.

    Returns the total number of ternary operators instrumented.
    """
    with open(input_path, 'r') as fh:
        lines = fh.readlines()

    output_lines = []
    module_ternaries = []       # list of (parsed_info, local_index)
    in_module = False
    module_name = ''
    local_counter = 0           # per-module counter
    total_counter = 0           # across all modules

    # Multi-line statement accumulator (list of parts for efficiency)
    pending_parts = []

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # ---- module start --------------------------------------------------
        mod_m = re.match(r'\s*module\s+(\w+)', stripped)
        if mod_m and not in_module:
            in_module = True
            module_name = mod_m.group(1)
            module_ternaries = []
            local_counter = 0
            output_lines.append(line)
            i += 1
            continue

        # ---- endmodule -----------------------------------------------------
        if re.match(r'\s*endmodule\b', stripped) and in_module:
            # Flush any pending multi-line statement (safety)
            if pending_parts:
                tern = parse_ternary(' '.join(pending_parts))
                if tern:
                    module_ternaries.append((tern, local_counter))
                    local_counter += 1
                    total_counter += 1
                pending_parts = []

            # Insert accumulated instrumentation
            if module_ternaries:
                output_lines.append(
                    f'\n  // === Ternary Instrumentation for module'
                    f' {module_name} ({len(module_ternaries)} ternaries)'
                    f' ===\n'
                )
                for tern_info, idx in module_ternaries:
                    for instr_line in generate_instrumentation(tern_info, idx):
                        output_lines.append(instr_line + '\n')
                    output_lines.append('\n')
                output_lines.append(
                    f'  // === End Instrumentation for module'
                    f' {module_name} ===\n\n'
                )

            output_lines.append(line)
            in_module = False
            i += 1
            continue

        # ---- outside any module – just copy --------------------------------
        if not in_module:
            output_lines.append(line)
            i += 1
            continue

        # ---- multi-line accumulation ---------------------------------------
        # Strip comments to detect the real end of a statement.
        stripped_no_comment = _strip_comment(stripped).rstrip()

        if pending_parts:
            pending_parts.append(stripped)
            output_lines.append(line)
            if stripped_no_comment.endswith(';'):
                tern = parse_ternary(' '.join(pending_parts))
                if tern:
                    module_ternaries.append((tern, local_counter))
                    local_counter += 1
                    total_counter += 1
                pending_parts = []
            i += 1
            continue

        # ---- detect start of a wire/assign that may span lines -------------
        is_wire_or_assign = (
            stripped.startswith('wire ')
            or stripped.startswith('assign ')
        )

        if is_wire_or_assign and not stripped_no_comment.endswith(';'):
            pending_parts = [stripped]
            output_lines.append(line)
            i += 1
            continue

        # ---- single-line wire/assign: try ternary parse --------------------
        if is_wire_or_assign:
            tern = parse_ternary(stripped)
            if tern:
                module_ternaries.append((tern, local_counter))
                local_counter += 1
                total_counter += 1

        output_lines.append(line)
        i += 1

    with open(output_path, 'w') as fh:
        fh.writelines(output_lines)

    return total_counter


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input.sv> [output.sv]")
        sys.exit(1)

    input_file = sys.argv[1]

    if len(sys.argv) >= 3:
        output_file = sys.argv[2]
    else:
        base, ext = os.path.splitext(input_file)
        output_file = f"{base}_instrumented{ext}"

    if not os.path.isfile(input_file):
        print(f"Error: input file '{input_file}' not found.")
        sys.exit(1)

    total = instrument_file(input_file, output_file)
    print(f"Instrumented {total} ternary operators.")
    print(f"Output written to: {output_file}")
