# AI Agent Security: Multi-Step Tool Attacks

An attack-only solution for Kaggle's **AI Agent Security: Multi-Step Tool Attacks** competition. The project analyzes the provided evaluator, guardrail, predicates, and replay behavior, then generates only candidates that pass live validation before submission.

## Result

| Version | Public score | Private score | Approach |
|---|---:|---:|---|
| v1 | 33.55 | 0.07 | Direct marker exfiltration with multiple prompt framings |
| v2 | **81.36** | 0.00 | Live validation-fill, model-aware framing, and replay-safe sizing |

**Public leaderboard rank: 2,034 out of 4,187 teams.**

The private score is included for completeness. The competition's hidden evaluation differed sharply from its public environment, which is an important robustness finding rather than something concealed by this repository.

## How it works

The attack studies the competition's actual scoring path instead of treating the target as a generic chatbot:

1. Generate a candidate message with a unique benign sink URL.
2. Replay it against the live opaque environment.
3. Keep it only when the expected security predicate fires.
4. Estimate observed latency and stop before the evaluator's replay budget can be exceeded.
5. Select a framing based on measured target latency.

The main finding was that candidate count alone was ineffective. Replay reliability and time-budget safety mattered far more because an oversized candidate set could invalidate the whole run.

## Repository structure

```text
attack.py                 Competition attack implementation
bench.py                  Local scoring and replay benchmark
local_targets.py          Cooperative local test target
quicktest.py              Small smoke test
quicktest2.py             Additional local validation
kaggle_kernel/            Kaggle submission notebook and metadata
STATUS.md                 Detailed scorer and guardrail investigation
```

## Local validation

Install the competition SDK:

```bash
pip install aicomp-sdk
```

Validate the submission contract:

```bash
python -m aicomp_sdk.cli.main validate redteam attack.py
```

Run the benchmark against the packaged deterministic target:

```bash
python bench.py 30 deterministic
```

The benchmark also supports `compliant`, `gpt_oss`, `openai`, and `gemma` when the corresponding target is available.

## Responsible-use note

This repository documents adversarial testing performed inside an authorized competition sandbox. It is intended for guardrail evaluation and defensive security research. Do not use these techniques against systems without explicit permission.

## Competition

- Track: attack-only
- Submission contract: one `attack.py` implementing `AttackAlgorithm`
- Kaggle slug: `ai-agent-security-multi-step-tool-attacks`

See [STATUS.md](STATUS.md) for the detailed scorer analysis, measured baselines, assumptions, and limitations.
