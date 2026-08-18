import sys; sys.path.insert(0, ".")
from bench import evaluate
import attack
class A(attack.AttackAlgorithm):
    def __init__(self, config=None):
        super().__init__({"slowest0":0.02,"slowest_mult":1.2,"margin_s":0.1,
                          "floor_min":0.02,"slowest_coef":1.0,"replay_safe_frac":0.9,
                          "fill_budget_frac":0.85,"hard_n_cap":60,"split_classify_n":4,
                          "split_threshold_s":0.05})
s, n = evaluate(A, budget_s=20, agent_selection="compliant")
print("score", round(s["score"],2), "raw", s["score_raw"], "valid", s["findings_count"],
      "cells", s["unique_cells"], "cand_returned", n)
