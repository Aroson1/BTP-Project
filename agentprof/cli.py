import argparse
import json
from pathlib import Path

from .policy import materialise, synthesise
from .runtime import doctor, run
from .select import register, select


def main():
    parser = argparse.ArgumentParser(description="Learn and enforce profiles for known Linux workflows")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("doctor")
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("--output", default="/results/linux-run")
    evaluate.add_argument("--repeats", type=int, default=3)
    learn = commands.add_parser("learn", help="Run a command in a disposable learning environment")
    learn.add_argument("--workflow", required=True)
    learn.add_argument("--output", required=True)
    learn.add_argument("command", nargs=argparse.REMAINDER)
    synth = commands.add_parser("synthesise")
    synth.add_argument("traces", nargs="+")
    synth.add_argument("--workflow", required=True)
    synth.add_argument("--output", required=True)
    synth.add_argument("--templates", action="store_true")
    synth.add_argument("--support", type=float, default=0)
    bound = commands.add_parser("synthesise-bound", help="Infer resource roles from trace/binding sample JSON")
    bound.add_argument("samples", nargs="+")
    bound.add_argument("--workflow", required=True)
    bound.add_argument("--output", required=True)
    bound.add_argument("--include-rare", action="store_true")
    reg = commands.add_parser("register")
    reg.add_argument("profile")
    reg.add_argument("--registry", required=True)
    reg.add_argument("--context", required=True, help="JSON with repository, environment and workflow_version")
    choose = commands.add_parser("select")
    choose.add_argument("--registry", required=True)
    choose.add_argument("--context", required=True)
    choose.add_argument("--workflow")
    choose.add_argument("--request")
    enforce = commands.add_parser("run")
    source = enforce.add_mutually_exclusive_group(required=True)
    source.add_argument("--profile")
    source.add_argument("--registry")
    enforce.add_argument("--context")
    enforce.add_argument("--workflow")
    enforce.add_argument("--request")
    enforce.add_argument("--bindings", help="Trusted task input/output JSON for a request-bound profile")
    enforce.add_argument("--record", action="store_true", help="Diagnostic strace, not a kernel audit log")
    enforce.add_argument("--rollback-on-failure", action="store_true", help="Restore the disposable workspace after a nonzero exit")
    enforce.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.action == "doctor":
        print(json.dumps(doctor(), indent=2))
    elif args.action == "evaluate":
        from benchmarks.evaluate import evaluate as evaluate_suite
        if not 1 <= args.repeats <= 10:
            parser.error("repeats must be between 1 and 10")
        evaluate_suite(args.output, args.repeats)
    elif args.action == "learn":
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command:
            parser.error("a command is required")
        result = run(command, record=True)
        if result["exit_code"]:
            raise SystemExit(result["stderr"])
        Path(args.output).write_text(json.dumps(result["trace"], indent=2))
    elif args.action == "synthesise":
        if not 0 <= args.support <= 1:
            parser.error("support must be between 0 and 1")
        profile = synthesise([json.loads(Path(p).read_text()) for p in args.traces], args.workflow,
                             generalise=args.templates, support=args.support)
        Path(args.output).write_text(json.dumps(profile, indent=2))
    elif args.action == "synthesise-bound":
        from .bound import synthesise_bound
        profile = synthesise_bound([json.loads(Path(p).read_text()) for p in args.samples], args.workflow,
                                   include_rare=args.include_rare)
        Path(args.output).write_text(json.dumps(profile, indent=2))
    elif args.action == "register":
        print(register(json.loads(Path(args.profile).read_text()), args.registry, json.loads(args.context)))
    elif args.action == "select":
        print(json.dumps(select(args.registry, json.loads(args.context), workflow=args.workflow, request=args.request), indent=2))
    elif args.action == "run":
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command:
            parser.error("a command is required")
        if args.registry:
            if not args.context:
                parser.error("registry selection requires --context")
            profile = select(args.registry, json.loads(args.context), workflow=args.workflow, request=args.request)
        else:
            profile = json.loads(Path(args.profile).read_text())
        result = run(command, profile=profile, record=args.record, rollback=args.rollback_on_failure,
                     bindings=json.loads(args.bindings) if args.bindings else None)
        print(json.dumps(result, indent=2))
        raise SystemExit(result["exit_code"])
