"""CLI scheduler for synthetic evaluations.

Examples:
  python -m simulation.cli run
  python -m simulation.cli schedule --interval-seconds 3600
"""
import argparse
import json
import time
from simulation.runner import run_simulation


def main():
    parser = argparse.ArgumentParser(description="Cloud Guardian offline attack-simulation evaluator")
    sub = parser.add_subparsers(dest="command", required=True)
    run_parser = sub.add_parser("run", help="run one synthetic scenario batch")
    run_parser.add_argument("--threshold", type=int, default=None)
    sched = sub.add_parser("schedule", help="run repeated synthetic batches on an interval")
    sched.add_argument("--interval-seconds", type=int, default=3600)
    sched.add_argument("--threshold", type=int, default=None)
    args = parser.parse_args()
    if args.command == "run":
        print(json.dumps(run_simulation(severity_threshold=args.threshold), indent=2))
        return
    if args.interval_seconds < 60:
        parser.error("Scheduled interval must be at least 60 seconds.")
    try:
        while True:
            report = run_simulation(severity_threshold=args.threshold)
            print(json.dumps({
                "run_id": report["run_id"],
                "scenario_count": report["scenario_count"],
                "metrics": report["metrics"],
                "report_path": report["report_path"],
            }, indent=2), flush=True)
            time.sleep(args.interval_seconds)
    except KeyboardInterrupt:
        print("Scheduler stopped.")


if __name__ == "__main__":
    main()
