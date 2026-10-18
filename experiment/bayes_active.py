"""Bayesian hidden-state model + approximate one-step POMDP KIE controller.

The model is *not* an exact general POMDP solution: it is a factorized
two-state Bayesian filter, with neighbor-dependent Markov transition
priors and a one-step, entropy/risk active-sensing approximation.
Each KIE is a genuine signed LAB agent receipt count (NOT native 5GC).

All parameters fitted only to independently collected PRIOR full-polling
agent data; test labels and future observations never enter the filter.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import pandas as pd

from experiment.features import NODES, NEIGHBORS

KIND = "PRIOR_REAL_SIGNED_FULL_KIE_BAYESIAN_2STATE_V1"
PROVENANCE = "LIVE_EIGHT_AUTHENTICATED_KIE_HTTP11_AND_OPEN5GS_HTTP2"
BUDGET = 2
ONSET_ALPHA, ONSET_BETA = 1.0, 25.0
SENS_ALPHA, SENS_BETA = 2.0, 2.0
EPS = 1e-6


def clamp(p: float) -> float:
    return max(EPS, min(1 - EPS, float(p)))


def entropy(p: float) -> float:
    p = clamp(p)
    return -p * math.log2(p) - (1 - p) * math.log2(1 - p)


def bayes_update(prior: float, observed_positive: bool,
                 sensitivity: float, false_positive: float) -> float:
    """Binary Bayes rule: P(hidden fault | verified signed observation)."""
    p = clamp(prior)
    s, f = clamp(sensitivity), clamp(false_positive)
    likelihood_attack = s if observed_positive else (1 - s)
    likelihood_ok = f if observed_positive else (1 - f)
    return clamp(p * likelihood_attack /
                 (p * likelihood_attack + (1 - p) * likelihood_ok))


def _validate_pilot(df: pd.DataFrame) -> list[int]:
    required = {"trial", "tick", "policy", "node", "label",
                "kie_gap_full", "kie_valid", "kie_queried",
                "provenance"}
    if required - set(df):
        raise ValueError(f"Bayesian fitting requires {sorted(required - set(df))}")
    if set(df.provenance.unique()) != {PROVENANCE}:
        raise ValueError("Bayesian model requires previously collected REAL KIE reports")
    if set(df.policy.unique()) != {"full"}:
        raise ValueError("Bayesian prior must use FULL-polling historical data only")
    if not df.kie_valid.eq(1).all() or not df.kie_queried.eq(1).all():
        raise ValueError("Missing signature-verified FULL historical KIE")
    if df.kie_gap_full.isna().any():
        raise ValueError("Missing historical verified KIE counter gap")
    if df.label.isna().any() or not df.label.isin([0, 1]).all():
        raise ValueError("Invalid historical experiment intervention labels")
    trials = sorted(map(int, df.trial.unique()))
    if len(trials) < 5:
        raise ValueError("Need >=5 prior independent FULL acquisition trials")
    for tr, tdf in df.groupby("trial", sort=True):
        ticks = sorted(map(int, tdf.tick.unique()))
        if len(ticks) < 20 or ticks != list(range(len(ticks))):
            raise ValueError(f"Incomplete pilot tick sequence {tr}")
        for t, block in tdf.groupby("tick"):
            if len(block) != len(NODES) or set(block.node) != set(NODES):
                raise ValueError(f"Incomplete historical 8NF grid trial={tr} tick={t}")
    if df.duplicated(["trial", "tick", "node"]).any():
        raise ValueError("Duplicate historical node observation")
    return trials


def fit(path: Path, output: Path) -> dict:
    """Beta-smoothed Markov/emission prior; last historic trial for validation.

    Labels here are controlled *prior* experimental intervention labels,
    not native 5G attacks. Validation has NO influence on hyperparameters.
    """
    df = pd.read_csv(path)
    trials = _validate_pilot(df)
    train_ids, validation_id = trials[:-1], trials[-1]
    train = df[df.trial.isin(train_ids)].copy()
    # Count conditional transitions using ONLY lagged historic truth.
    counts = {"quiet": [0, 0], "neighbor": [0, 0], "persist": [0, 0]}
    examples = []
    for tr, block in train.groupby("trial", sort=True):
        ordered = list(block.groupby("tick", sort=True))
        previous = None
        for tick, tick_df in ordered:
            now = {str(r.node): int(r.label) for r in tick_df.itertuples()}
            if previous is not None:
                for n in NODES:
                    neighbor_active = any(previous[k] for k in NEIGHBORS[n])
                    category = ("persist" if previous[n] else
                                "neighbor" if neighbor_active else "quiet")
                    counts[category][1] += 1
                    if now[n]:
                        counts[category][0] += 1
            previous = now
    # Small-data shrinkage: stronger prior for rare spontaneous onsets,
    # nonzero persistence and neighbor-conditional interventions.
    quiet_yes, quiet_all = counts["quiet"]
    neighbor_yes, neighbor_all = counts["neighbor"]
    persist_yes, persist_all = counts["persist"]
    onset = (quiet_yes + ONSET_ALPHA) / (quiet_all + ONSET_ALPHA + ONSET_BETA)
    with_neighbor = (neighbor_yes + 1.) / (neighbor_all + 15.)
    persistence = (persist_yes + 3.) / (persist_all + 4.)
    lift = max(0., min(.35, with_neighbor - onset))
    positive = train.kie_gap_full.astype(float).gt(0)
    truth = train.label.eq(1)
    yes_true, total_true = int((positive & truth).sum()), int(truth.sum())
    yes_false, total_false = int((positive & ~truth).sum()), int((~truth).sum())
    sensitivity = (yes_true + SENS_ALPHA) / (total_true + SENS_ALPHA + SENS_BETA)
    false_positive = (yes_false + 1.) / (total_false + 40.)
    initial = (int(truth.sum()) + 1) / (len(truth) + 40.)
    if total_true < 10 or not (0 < onset < 1 and 0 < persistence < 1):
        raise ValueError("Insufficient valid historical fault state transitions")
    params = {
        "kind": KIND, "source": str(path),
        "fit_trials": train_ids, "validation_trial": validation_id,
        "counts_training_only": counts,
        "initial_fault_probability": clamp(initial),
        "onset_quiet": clamp(onset), "neighbor_lift": float(lift),
        "persist_probability": clamp(persistence),
        "signed_emission_sensitivity": clamp(sensitivity),
        "signed_emission_false_positive": clamp(false_positive),
        "transition_semantics": "lagged previous NF fault belief and previous neighbor belief",
        "feature_scope": "only past KIEs, their masks/age and lagged real SBA",
        "exact_pomdp_solver": False,
        "optimizer": "one-step expected verification benefit and Bayesian entropy reduction",
        "fixed_utility": {
            "verification_reward": 1.0,
            "current_entropy_weight": 1.0,
            "neighbor_next_entropy_weight": 2.0,
            "query_cost_per_nf": 0.005,
            "maximum_probe_age": 8,
        },
        "training_provenance": "prior genuinely HMAC-verified FULL polling; labels are staged lab agent counter faults",
        "native_nf_counters": False,
        "test_schedule_seed_seen_during_fit": False,
    }
    # One-step historic validation log-loss, no threshold or params tuned.
    filt = BayesianFilter(params, use_edges=True)
    val_rows = []
    for tick, block in df[df.trial == validation_id].groupby("tick", sort=True):
        if tick == 0:
            filt.reset()
        else:
            filt.forecast()
        before = filt.belief.copy()
        for n, row in block.set_index("node").iterrows():
            val_rows.append((before[n], int(row["label"])))
            filt.observe(n, float(row["kie_gap_full"]) > 0)
    params["untuned_validation_mean_log_loss"] = sum(
        -(y*math.log(clamp(p)) + (1-y)*math.log(1-clamp(p)))
        for p, y in val_rows) / len(val_rows)
    output.parent.mkdir(exist_ok=True, parents=True)
    output.write_text(json.dumps(params, indent=2, allow_nan=False), encoding="utf8")
    return params


class BayesianFilter:
    """Hidden fault/not-fault marginal; no future KIE or label observation."""
    def __init__(self, params: dict, use_edges: bool = True):
        if params.get("kind") != KIND:
            raise ValueError("Unrecognized frozen Bayesian model")
        self.p = params
        self.use_edges = bool(use_edges)
        self.reset()

    def reset(self) -> None:
        self.belief = {n: float(self.p["initial_fault_probability"]) for n in NODES}
        self.last_observation = {n: False for n in NODES}

    def neighbor_probability(self, node: str, state: dict[str, float]) -> float:
        if not self.use_edges or not NEIGHBORS[node]:
            return 0.0
        # Prob(at least one neighbor is faulty), mean-field assumption.
        product = 1.0
        for other in NEIGHBORS[node]:
            product *= 1.0 - clamp(state[other])
        return 1.0 - product

    def predict_node(self, node: str, state: dict[str, float]) -> float:
        p = clamp(state[node])
        hazard = clamp(self.p["onset_quiet"] +
                       self.p["neighbor_lift"] * self.neighbor_probability(node, state))
        return clamp(p * self.p["persist_probability"] + (1-p) * hazard)

    def forecast(self) -> None:
        old = dict(self.belief)
        self.belief = {n: self.predict_node(n, old) for n in NODES}

    def observe(self, node: str, signed_gap_positive: bool) -> None:
        if node not in self.belief:
            raise ValueError("Unknown signed NF observation")
        self.belief[node] = bayes_update(
            self.belief[node], bool(signed_gap_positive),
            self.p["signed_emission_sensitivity"],
            self.p["signed_emission_false_positive"])
        self.last_observation[node] = True

    def observation_outcomes(self, node: str) -> tuple[float, float, float]:
        prior = clamp(self.belief[node])
        sens = self.p["signed_emission_sensitivity"]
        fp = self.p["signed_emission_false_positive"]
        q = clamp(prior*sens + (1-prior)*fp)
        return q, bayes_update(prior, True, sens, fp), bayes_update(prior, False, sens, fp)


class ActiveBayesian:
    """Approximate POMDP one-step value of signed information under 2/8 budget.

    greedy double choice with frozen utility weights. 'entropy' is an
    ablation (same posterior but no verification reward or future peers).
    'no_edges' removes learned relationship in belief and VOI term.
    """
    def __init__(self, path: Path, mode: str = "pomdp"):
        if mode not in ("pomdp", "entropy", "no_edges"):
            raise ValueError("Unknown Bayesian ablation mode")
        self.params = json.loads(path.read_text(encoding="utf8"))
        self.mode = mode
        self.filter = BayesianFilter(self.params, use_edges=mode != "no_edges")
        self.last_tick = -1
        self.last_scores: dict[str, float] = {}
        self.observation_pending = set()

    def before(self, tick: int, states: dict, last_sba: dict,
               budget: int = BUDGET) -> set[str]:
        if tick != self.last_tick + 1:
            raise ValueError("Cannot use a future/out-of-order live KIE tick")
        if budget != BUDGET:
            raise ValueError("Signed KIE budget must stay 2/8")
        self.last_tick = tick
        if tick:
            self.filter.forecast()
        if tick == 0:
            # Start with same eight authenticated observations as all policies.
            self.observation_pending = set(NODES)
            self.last_scores = {n: 0. for n in NODES}
            return set(NODES)
        if set(states) != set(NODES) or set(last_sba) != set(NODES):
            raise ValueError("Incomplete lagged eight-NF inputs")
        scores = {n: self.value_of_information(n) for n in NODES}
        self.last_scores = scores
        # Bounded age fairness avoids indefinitely withholding KIE from
        # a nonanomalous node. This is explicitly part of ALL restricted
        # schedulers' safety policy, not an attack-target oracle.
        overdue = [n for n in NODES if states[n]["age"] >=
                   self.params["fixed_utility"]["maximum_probe_age"]]
        ordered_overdue = sorted(overdue, key=lambda n: (-states[n]["age"], -scores[n], n))
        chosen = list(ordered_overdue[:budget])
        remaining = [n for n in NODES if n not in chosen]
        while len(chosen) < budget:
            # Greedy pair diversity discourages wasting a 2-KIE batch on
            # recipients with many overlapping neighbors. Same frozen rule
            # regardless of attack seed; no current KIE responses.
            def marginal(n: str) -> tuple[float, str]:
                overlap = sum(len(NEIGHBORS[n] & NEIGHBORS[other])
                              for other in chosen) if self.mode != "no_edges" else 0
                return (scores[n] - 0.01*overlap, n)
            best = max(remaining, key=marginal)
            chosen.append(best)
            remaining.remove(best)
        self.observation_pending = set(chosen)
        return set(chosen)

    def value_of_information(self, node: str) -> float:
        f = self.filter
        prior = f.belief[node]
        q, post_pos, post_neg = f.observation_outcomes(node)
        entropy_reduction = max(
            0., entropy(prior) - q*entropy(post_pos) -
            (1-q)*entropy(post_neg))
        if self.mode == "entropy":
            return entropy_reduction
        sensitivity = f.p["signed_emission_sensitivity"]
        reward = prior * sensitivity
        future_gain = 0.0
        if self.mode == "pomdp":
            # Expected one-step reduction in uncertainty of *other* NFs
            # given either signed response at node. A current KIE cannot
            # directly reveal unqueried neighbors; it refines a posterior
            # prediction based on learned neighbor Markov dependence.
            state = dict(f.belief)
            for other in NODES:
                if other == node or node not in NEIGHBORS[other]:
                    continue
                base = f.predict_node(other, state)
                state[node] = post_pos
                plus = f.predict_node(other, state)
                state[node] = post_neg
                minus = f.predict_node(other, state)
                state[node] = prior
                future_gain += max(0., entropy(base) -
                                   q*entropy(plus) - (1-q)*entropy(minus))
        utility = self.params["fixed_utility"]
        return (utility["verification_reward"]*reward +
                utility["current_entropy_weight"]*entropy_reduction +
                utility["neighbor_next_entropy_weight"]*future_gain -
                utility["query_cost_per_nf"])

    def observe(self, node: str, gap: float) -> None:
        if node not in self.observation_pending:
            raise RuntimeError("Cannot consume a current or hypothetical unqueried KIE")
        self.filter.observe(node, gap > 0)
        self.observation_pending.remove(node)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, default=Path("results/eight_full_training.csv"))
    p.add_argument("--output", type=Path, default=Path("results/eight_bayes_frozen.json"))
    args = p.parse_args()
    print(json.dumps(fit(args.input, args.output), indent=2))


if __name__ == "__main__":
    main()
