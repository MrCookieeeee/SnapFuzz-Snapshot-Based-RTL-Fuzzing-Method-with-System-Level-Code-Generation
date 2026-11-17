import os
import sys
import argparse

from fuzzer import task_distribute
from common.GetCfgs import get_design_cfg
from common.TolerateBugs import tolerate_bug_for_eval_reduction
from common.path import get_data_dir, get_merged_line_cov_path, get_merged_br_cov_path

# ============================================================================================
# sys.argv[1]: design name
# sys.argv[2]: tolerate some bug (by default 0)
# python3 src/do_fuzz_design.py <design_name> [<tolerate_some_bug>] [--no-update] [--generate-only [True|False]]
# ============================================================================================


def _parse_bool(value):
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    raise argparse.ArgumentTypeError("expected True or False")


def main(argv=None):
    argv = sys.argv if argv is None else argv

    if "SNAPFUZZ_DIR" not in os.environ:
        raise Exception("The SnapFuzz environment must be sourced prior to running the Python recipes.")

    parser = argparse.ArgumentParser(description="Generate SnapFuzz ELFs or run coverage-guided RTL fuzzing.")
    parser.add_argument("design_name")
    parser.add_argument("tolerate_some_bug", nargs="?", type=int, default=0)
    parser.add_argument("--no-update", action="store_true", default=False,
                        help="Disable coverage feedback and instruction probability updates.")
    parser.add_argument("--generate-only", type=_parse_bool, nargs="?", const=True, default=True,
                        metavar="{True,False}",
                        help="Generate ELFs using Spike resolution without RTL execution (default: True).")
    args = parser.parse_args(argv[1:])
    get_design_cfg(args.design_name)
    if args.tolerate_some_bug:
        tolerate_bug_for_eval_reduction(args.design_name)

    design_name = args.design_name
    get_data_dir().mkdir(parents=True, exist_ok=True)
    if not args.generate_only:
        # Clean cov merged data file
        # Create the file if missing; truncate to empty if it already exists
        line_cov_merged_file = get_merged_line_cov_path(design_name)
        line_cov_merged_file.parent.mkdir(parents=True, exist_ok=True)
        line_cov_merged_file.write_text("")

        br_cov_merged_file = get_merged_br_cov_path(design_name)
        br_cov_merged_file.write_text("")


    # Lets Fuzz
    task_distribute(
        design_name,
        16,
        seed_offset=0,
        can_authorize_privileges=True,
        no_update=args.no_update,
        generate_only=args.generate_only,
    )


if __name__ == '__main__':
    main()
