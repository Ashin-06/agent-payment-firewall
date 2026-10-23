"""Public real-world tests for the firewall.

1. The injection detector on prompts written by people:
   - Lakera Gandalf "ignore instructions" (MIT): 1,000 real attempts by players trying to make
     an LLM reveal a password. All are attacks.
   - deepset/prompt-injections (Apache-2.0): 662 prompts labelled injection / benign, English
     and German.
2. The whole firewall on AgentDojo's banking suite (see agentdojo.py).

    python -m agentfw realdata --gandalf gandalf_ignore_instructions/ --deepset prompt-injections/ \
        --agentdojo agentdojo_banking.json
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from .detector import scan


def _parquets(folder: str | Path) -> pd.DataFrame:
    return pd.concat([pd.read_parquet(p) for p in sorted(Path(folder).rglob("*.parquet")) if ".cache" not in p.parts],
                     ignore_index=True)


def _rates(texts: list[str]) -> dict:
    scores = [scan(t).score for t in texts]
    return {"n": len(texts),
            "flagged_medium_or_high": round(sum(s >= 2 for s in scores) / max(len(scores), 1), 4),
            "flagged_high": round(sum(s >= 4 for s in scores) / max(len(scores), 1), 4)}


def injection_text(gandalf: str | Path | None, deepset: str | Path | None) -> dict:
    out = {}
    if gandalf:
        # the detector patterns were broadened using the train split only; validation and test are held out
        for split in ("train", "validation", "test"):
            files = sorted(p for p in Path(gandalf).rglob(f"{split}-*.parquet") if ".cache" not in p.parts)
            out[f"gandalf_{split}"] = _rates(pd.concat(pd.read_parquet(f) for f in files)["text"].astype(str).tolist())
    if deepset:
        d = _parquets(deepset)
        out["deepset_injections"] = _rates(d.loc[d["label"] == 1, "text"].astype(str).tolist())
        out["deepset_benign_false_alarms"] = _rates(d.loc[d["label"] == 0, "text"].astype(str).tolist())
    return out


def main(gandalf=None, deepset=None, agentdojo=None, out="results/real_data.json") -> dict:
    res = {"injection_detector": injection_text(gandalf, deepset)}
    if agentdojo:
        from .agentdojo import run

        r = run(agentdojo)
        res["agentdojo_banking"] = {k: v for k, v in r.items() if not k.startswith("per_")}
        res["agentdojo_banking"]["per_user_task"] = r["per_user_task"]
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(res, indent=2))
    return res
