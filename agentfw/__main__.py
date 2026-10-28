"""Command line.

    python -m agentfw bench [--live] [--only A01 B02]
    python -m agentfw chat "Pay the Acme invoice inv-2291" [--no-firewall]
    python -m agentfw scan path/to/email.txt
    python -m agentfw realdata --gandalf DIR --deepset DIR --agentdojo agentdojo_banking.json
    python -m agentfw serve                        # console (settings: AGENTFW_* env)
    python -m agentfw migrate                      # apply database migrations and exit
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .bank import Bank
from .bench import SCENARIOS, run, summary
from .detector import scan
from .gateway import Gateway


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(prog="agentfw")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bench", help="attack/utility benchmark")
    b.add_argument("--live", action="store_true", help="drive a real LLM assistant instead of fixed traces")
    b.add_argument("--only", nargs="*")
    b.add_argument("--json")
    c = sub.add_parser("chat", help="one request to the LLM assistant through the firewall")
    c.add_argument("message")
    c.add_argument("--no-firewall", action="store_true")
    s = sub.add_parser("scan", help="injection scan of a text file")
    s.add_argument("file")
    r = sub.add_parser("realdata", help="detector on real injection prompts, firewall on AgentDojo banking")
    r.add_argument("--gandalf", help="Lakera/gandalf_ignore_instructions download")
    r.add_argument("--deepset", help="deepset/prompt-injections download")
    r.add_argument("--agentdojo", help="JSON from python -m agentfw.agentdojo_export")
    r.add_argument("--out", default="results/real_data.json")
    v = sub.add_parser("serve")
    v.add_argument("--port", type=int, help="default AGENTFW_PORT or 8004")
    v.add_argument("--host", help="default AGENTFW_HOST or 127.0.0.1; any other address needs API keys")
    sub.add_parser("migrate", help="apply database migrations to AGENTFW_DATABASE_URL")
    a = ap.parse_args(argv)

    if a.cmd == "bench":
        rows = run(live=a.live, ids=a.only)
        for r in rows:
            if r["kind"] == "attack":
                print(f"{r['id']}  {r['title'][:62]:62s}  no firewall: {r['without_firewall']:9s}  firewall: {r['with_firewall']}")
            else:
                mark = "ok" if r["ok"] else "UNEXPECTED"
                print(f"{r['id']}  {r['title'][:62]:62s}  firewall: {r['with_firewall']:8s} (expected {r['expected']}) {mark}")
            for tool, status, why in r["decisions"]:
                print(f"       {tool} {status}: {why.split(' Do not retry')[0].split(' Nothing has been sent')[0][:160]}")
        s = summary(rows)
        print(f"\nattack success: {s['attack_success_without_firewall']:.0%} without firewall -> {s['attack_success_with_firewall']:.0%} with firewall"
              f"  ({s['attacks']} attacks)")
        print(f"benign tasks: {s['benign_blocked']:.0%} wrongly blocked, {s['benign_held']:.0%} held for confirmation, "
              f"{s['benign_as_expected']:.0%} as expected  ({s['benign']} tasks)")
        if a.json:
            Path(a.json).write_text(json.dumps({"rows": rows, "summary": s}, indent=2, ensure_ascii=False), encoding="utf-8")
    elif a.cmd == "chat":
        from .agent import LLMAgent

        bank = Bank.demo()
        for sc in sorted(SCENARIOS, key=lambda s: s.kind != "benign"):  # poisoned versions win shared ids
            bank.documents.update(sc.docs)
        gw = Gateway(bank, enforce=not a.no_firewall)
        res = LLMAgent(gw).run(a.message)
        for st in res.steps:
            print(f"  {st.tool} {json.dumps(st.args, ensure_ascii=False)} -> {st.status}")
        print("\n" + res.text)
        for p in gw.approvals.pending():
            print(f"\npending approval {p.id}: {p.tool} {p.args}\n  " + "\n  ".join(p.reasons))
    elif a.cmd == "scan":
        r = scan(open(a.file, encoding="utf-8").read())
        print(f"injection score {r.score:.1f} ({r.level})")
        for f in r.findings:
            print(f"  - {f.kind} (+{f.weight}): {f.excerpt}")
    elif a.cmd == "realdata":
        from .realdata import main as realdata

        print(json.dumps(realdata(a.gandalf, a.deepset, a.agentdojo, a.out), indent=2))
    elif a.cmd == "migrate":
        from . import db, ops

        applied = db.migrate(db.engine(ops.load_settings().database_url))
        print(*(applied or ["up to date"]), sep="\n")
    elif a.cmd == "serve":
        import uvicorn

        from . import ops

        for name, val in (("HOST", a.host), ("PORT", a.port)):
            if val is not None:
                os.environ[f"AGENTFW_{name}"] = str(val)
        try:
            settings = ops.load_settings()  # fail here, before uvicorn, with a readable message
        except ops.ConfigError as e:
            sys.exit(f"configuration error: {e}")
        if settings.production and not os.environ.get("ANTHROPIC_API_KEY"):
            sys.exit("configuration error: production needs ANTHROPIC_API_KEY for the assistant")
        ops.setup_logging(settings.log_level)
        uvicorn.run("agentfw.server:app", host=settings.host, port=settings.port, log_config=None, access_log=False)


if __name__ == "__main__":
    main()
