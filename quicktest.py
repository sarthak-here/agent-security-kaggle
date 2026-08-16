import sys; sys.path.insert(0, ".")
from bench import evaluate
import attack
# small cap for a fast end-to-end signal
class A(attack.AttackAlgorithm):
    def __init__(self, config=None):
        super().__init__({"max_candidates": 40})
s, n = evaluate(A, budget_s=3, agent_selection="compliant")
print("score", round(s["score"], 2), "raw", s["score_raw"],
      "valid", s["findings_count"], "cells", s["unique_cells"], "cand", n)
