"""Benchmark harness: measure attack algorithms against the scoring config.

Mirrors the Kaggle attack-only path (gym env, optimal_public guardrail, chosen
target agent) but drives the SDK primitives directly so the attacker's search
budget is decoupled from the evaluator's hard timeout (evaluate_redteam ties them
together, which makes tight-budget baseline runs race the deadline).

Usage: python bench.py [budget_s] [agent]
  agent in {deterministic, gpt_oss, openai, gemma}  (default deterministic)
"""

import sys
import time
from pathlib import Path

from aicomp_sdk.agents import AgentSelection, build_agent_factory
from aicomp_sdk.attacks import AttackCandidate, AttackRunConfig
from aicomp_sdk.core.cells import cell_signature
from aicomp_sdk.core.env.api import EnvSelection
from aicomp_sdk.core.env.opaque import _OpaqueAttackEnv
from aicomp_sdk.core.predicates import eval_predicates
from aicomp_sdk.evaluation.ops import (
    MAX_REPLAY_FINDINGS,
    build_attack_env,
    resolve_fixtures_dir,
    summarize_attack_findings,
)
from aicomp_sdk.guardrails.optimal import Guardrail as OptimalGuardrail
from aicomp_sdk.hooks import HookRegistry

SEED = 123
MAX_HOPS = 4


def evaluate(attack_cls, *, budget_s, agent_selection):
    fixtures = resolve_fixtures_dir(None)
    if agent_selection == "compliant":
        from local_targets import compliant_factory
        factory = compliant_factory
    else:
        factory = build_agent_factory(agent_selection)

    # --- generation phase (opaque env, attacker searches live) ---
    run_env = _OpaqueAttackEnv(
        build_attack_env(
            seed=SEED, fixtures_dir=fixtures, agent_factory=factory,
            guardrail=OptimalGuardrail(), env_selection=EnvSelection.GYM,
            max_tool_hops=MAX_HOPS, hook_registry=HookRegistry(),
        )
    )
    run_env.reset()
    attacker = attack_cls()
    cfg = AttackRunConfig(time_budget_s=budget_s, max_tool_hops=MAX_HOPS)
    candidates = attacker.run(run_env, cfg)

    # --- replay phase (fresh env per candidate, canonical scoring trace) ---
    validated = []
    for idx, cand in enumerate(candidates[:MAX_REPLAY_FINDINGS]):
        if not isinstance(cand, AttackCandidate):
            continue
        env = build_attack_env(
            seed=SEED, fixtures_dir=fixtures, agent_factory=factory,
            guardrail=OptimalGuardrail(), env_selection=EnvSelection.GYM,
            max_tool_hops=MAX_HOPS, hook_registry=HookRegistry(),
        )
        env.reset()
        for msg in cand.user_messages:
            env.interact(msg, max_tool_hops=MAX_HOPS)
        trace = env.export_trace_dict()
        preds = eval_predicates(trace)
        if not preds:
            continue
        validated.append({
            "seed": trace["seed"],
            "user_messages": list(trace.get("user_messages", [])),
            "trace": trace,
            "predicates": preds,
            "cell_signature": cell_signature(
                trace.get("tool_events", []),
                egress_data=trace.get("egress", []),
                user_messages=trace.get("user_messages", []),
            ),
            "score_cell_signature": cell_signature(trace.get("tool_events", [])),
        })
    return summarize_attack_findings(validated), len(candidates)


def run(attack_cls, label, budget_s, agent_selection):
    t0 = time.time()
    try:
        summary, n_cand = evaluate(attack_cls, budget_s=budget_s, agent_selection=agent_selection)
    except Exception as e:
        print(f"{label:<26} ERROR {type(e).__name__}: {e}")
        return
    dt = time.time() - t0
    print(
        f"{label:<26} score={summary['score']:8.2f} raw={summary['score_raw']:9.1f} "
        f"cand={n_cand:5d} valid={summary['findings_count']:5d} "
        f"cells={summary['unique_cells']:4d} ({dt:.1f}s)"
    )


AGENTS = {
    "deterministic": AgentSelection.DETERMINISTIC,
    "gpt_oss": AgentSelection.GPT_OSS,
    "openai": AgentSelection.OPENAI,
    "gemma": AgentSelection.GEMMA,
}


def main():
    budget_s = float(sys.argv[1]) if len(sys.argv) > 1 else 15.0
    agent = sys.argv[2] if len(sys.argv) > 2 else "deterministic"
    sel = AGENTS.get(agent, agent)  # "compliant" passes through as a string

    sys.path.insert(0, str(Path(__file__).parent))
    print(f"budget={budget_s}s  env=gym  agent={agent}  guardrail=optimal_public")
    print("=" * 92)

    from aicomp_sdk.attacks.baselines.attack_random import AttackAlgorithm as Rand
    from aicomp_sdk.attacks.baselines.attacker_goexplore import AttackAlgorithm as GoEx
    run(Rand, "baseline: random", budget_s, sel)
    run(GoEx, "baseline: go-explore", budget_s, sel)

    root = Path(__file__).parent
    if (root / "attack.py").exists():
        sys.path.insert(0, str(root))
        try:
            import importlib
            import attack as atk_mod
            importlib.reload(atk_mod)
            run(atk_mod.AttackAlgorithm, "ours: attack.py", budget_s, sel)
        except Exception as e:
            print(f"ours: attack.py            SKIPPED ({type(e).__name__}: {e})")


if __name__ == "__main__":
    main()
