"""Prospective 8-NF authenticated KIE scheduling with graph-correlated faults.

All signed messages are real HMAC-verified HTTP/1.1 interactions with eight
NF-colocated LAB AGENTS, not native Open5GS KIE counters. All low-cost
SBA probes are REAL HTTP/2 to the Open5GS NF listeners.

Attack topology is a *predeclared, deliberately graph-correlated agent
counter-falsification cascade*. This is a difficult probe scheduling
benchmark, NOT naturally spreading 5G malware or compromised NFs.
Policies never read the episode plan, phase/labels or future KIE reports.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import time
from pathlib import Path

from experiment.active8_graph import Risk, BUDGET, state_zero, transport_zero
from experiment.bayes_active import ActiveBayesian
from experiment.collect import probe
from experiment.features import NODES, NEIGHBORS
from experiment.secure_collect import authenticated_kie, docker

TICKS = 36
SCENARIO_SEED_TRAIN = 107
SCENARIO_SEED_TEST = 81491
PROVENANCE = "LIVE_EIGHT_AUTHENTICATED_KIE_HTTP11_AND_OPEN5GS_HTTP2"
ALL_POLICIES = ("full", "rotation", "local_heuristic", "neighbor_heuristic",
                "no_graph_gru", "graph_gru")
BAYES_POLICIES = ("bayes_entropy", "bayes_no_edges", "bayes_pomdp")
SUPPORTED_POLICIES = ALL_POLICIES + BAYES_POLICIES
COLS = ("trial", "policy", "tick", "node", "label", "sba_up",
        "sba_rtt_ms", "kie_queried", "kie_valid", "kie_gap_full",
        "kie_rtt_ms", "kie_age", "alarm", "signed_request_bytes",
        "signed_response_bytes", "risk_before", "provenance")


def scenario(seed: int, trial: int) -> list[dict]:
    """Two actual co-located agent counter faults followed by neighbor cascades.

    Uses only predeclared graph topology. Later node is sampled from
    functional neighbors; this deliberately makes graph structure
    predictive IN PRINCIPLE. It does not guarantee model advantage.
    """
    rng = random.Random(seed + trial * 1009)
    roots = rng.sample(list(NODES), 2)
    episodes = []
    for root, start in zip(roots, (7, 22)):
        candidates = sorted(NEIGHBORS[root] - {root})
        child = rng.choice(candidates)
        episodes.append({"node": root, "start": start, "end": start + 7,
                         "family": "origin", "cascade_from": None})
        episodes.append({"node": child, "start": start + 4, "end": start + 7,
                         "family": "neighbor_followup", "cascade_from": root})
    # Deliberately benign agent RTT increase outside all attacks.
    delay = rng.choice(list(NODES))
    episodes.append({"node": delay, "start": 16, "end": 20,
                     "family": "benign_delay", "cascade_from": None})
    return episodes


def active_nodes(episodes: list[dict], tick: int, family: str) -> set[str]:
    return {x["node"] for x in episodes
            if x["family"] == family and x["start"] <= tick < x["end"]}


def attack_nodes(episodes: list[dict], tick: int) -> set[str]:
    return {x["node"] for x in episodes
            if x["family"] != "benign_delay" and x["start"] <= tick < x["end"]}


def set_switches(previous: set[str], desired: set[str], mode: str) -> set[str]:
    if mode not in ("kie-spoof-counter-only", "kie-delay-only"):
        raise ValueError("Unrecognized only-test-agent intervention")
    for node in sorted(previous - desired):
        docker("exec", f"kie8-{node}", "rm", "-f", f"/tmp/{mode}")
    for node in sorted(desired - previous):
        docker("exec", f"kie8-{node}", "touch", f"/tmp/{mode}")
    return set(desired)


def rank(policy: str, tick: int, states: dict, rng: random.Random,
         risk: dict | None, budget: int = BUDGET, max_age: int = 6) -> set[str]:
    if policy == "full" or tick == 0:
        return set(NODES)
    if budget != BUDGET:
        raise ValueError("All limited policies must use identical budget=2")
    if policy == "rotation":
        return {NODES[(tick * budget + i) % len(NODES)] for i in range(budget)}
    scores = {}
    for n in NODES:
        s = states[n]
        overdue = 1000 if s["age"] >= max_age else 0
        if policy == "local_heuristic":
            score = .22 * s["age"] + .5 * min(s["gap"], 4)
        elif policy == "neighbor_heuristic":
            adjacent = max((min(states[k]["gap"], 4) for k in NEIGHBORS[n]), default=0)
            score = .20 * s["age"] + .55 * adjacent + .30 * min(s["gap"], 4)
        elif policy in ("graph_gru", "no_graph_gru") and risk is not None:
            score = 2 * float(risk[n]) + .13 * s["age"] + .25 * min(s["gap"], 4)
        else:
            raise ValueError("Unknown policy / missing independently trained risk")
        scores[n] = overdue + score + rng.random() * 1e-5
    return set(sorted(scores, key=lambda n: scores[n], reverse=True)[:budget])


def acquire(output: Path, policies: tuple[str, ...], trials: int,
            seed: int, model_root: Path | None, interval: float = .08,
            bayes_model: Path | None = None) -> dict:
    master = bytes.fromhex(os.environ["KIE_TEST_KEY"])
    if len(master) < 32:
        raise RuntimeError("Need ephemeral >=256bit HMAC key")
    if not 2 <= trials <= 14:
        raise ValueError("Need 2-14 genuine independent trials")
    if any(p not in SUPPORTED_POLICIES for p in policies):
        raise ValueError("Unsupported protocol policy")
    if len(set(policies)) != len(policies):
        raise ValueError("No duplicated policies")
    if any(p in ("graph_gru", "no_graph_gru") for p in policies) and model_root is None:
        raise ValueError("Frozen historical models must be supplied before prospective KIEs")
    if set(policies).intersection(BAYES_POLICIES) and bayes_model is None:
        raise ValueError("Bayesian actions require a FROZEN prior training JSON")
    output.parent.mkdir(parents=True, exist_ok=True)
    # Guaranteed fresh serials across separate invocations sharing live agents.
    seq = {n: time.time_ns() // 1000 for n in NODES}
    rng = random.Random(seed * 29)
    order = list(policies)
    rng.shuffle(order)
    interventions = []
    counts = {p: 0 for p in policies}
    active_spoof, active_delay = set(), set()
    try:
        with output.open("w", newline="", encoding="utf8") as handle:
            writer = csv.DictWriter(handle, fieldnames=COLS)
            writer.writeheader()
            for policy in order:
                for trial in range(trials):
                    plan = scenario(seed, trial)
                    interventions.append({"policy": policy, "trial": trial,
                                          "predeclared_agent_counter_modes": plan})
                    states = state_zero()
                    last_sba = transport_zero()
                    learner = None
                    bayesian = None
                    if policy in BAYES_POLICIES:
                        bayesian = ActiveBayesian(
                            bayes_model, mode={
                                "bayes_entropy": "entropy",
                                "bayes_no_edges": "no_edges",
                                "bayes_pomdp": "pomdp",
                            }[policy])
                    if policy in ("graph_gru", "no_graph_gru"):
                        learner = Risk(
                            model_root.with_name(f"{model_root.stem}-{policy}.pt"),
                            graph=(policy == "graph_gru"))
                    # Selection stochastic ties are seeded per campaign,
                    # different policies see the same precommitted
                    # target sequence but independent real HMAC replies.
                    local_rng = random.Random(seed * 100 + trial * 37
                                              + ALL_POLICIES.index(policy) * 10000)
                    for tick in range(TICKS):
                        present = attack_nodes(plan, tick)
                        delayed = active_nodes(plan, tick, "benign_delay")
                        active_spoof = set_switches(
                            active_spoof, present, "kie-spoof-counter-only")
                        active_delay = set_switches(
                            active_delay, delayed, "kie-delay-only")
                        # This is the ONLY model input point at this tick;
                        # no current SBA, labels, hidden episode targets,
                        # signed messages or future data have been used yet.
                        risks = learner.before(tick, states, last_sba) if learner else None
                        if bayesian is not None:
                            selected = bayesian.before(tick, states, last_sba)
                            risks = dict(bayesian.last_scores)
                        else:
                            selected = rank(policy, tick, states, local_rng, risks)
                        if tick > 0 and policy != "full" and len(selected) != BUDGET:
                            raise RuntimeError("Actual signed KIE budget violated")
                        current_sba = {n: probe(n, 2.5) for n in NODES}
                        last_sba = current_sba
                        obtained = {}
                        for n in NODES:
                            if n in selected:
                                seq[n] += 1
                                response = authenticated_kie(n, seq[n], master, timeout=3.)
                                if response["kie_valid"] != 1 or response["kie_invariant_error"]:
                                    raise RuntimeError("Signed challenge authentication/invariant failed")
                                s = states[n]
                                s["seen"] += 1
                                claimed = int(response["kie_claimed_received"])
                                if s["offset"] is None:
                                    s["offset"] = claimed - s["seen"]
                                gap = abs(s["seen"] + s["offset"] - claimed)
                                s.update(gap=float(gap), age=0,
                                         rtt=response["kie_rtt_ms"], selected=1)
                                # Bayes posterior updated AFTER actual authenticated
                                # response; current tick decision cannot use it.
                                if bayesian is not None:
                                    bayesian.observe(n, float(gap))
                                counts[policy] += 1
                                obtained[n] = {
                                    "kie_queried": 1, "kie_valid": 1,
                                    "kie_gap_full": gap,
                                    "kie_rtt_ms": response["kie_rtt_ms"],
                                    "signed_request_bytes": response["kie_request_bytes"],
                                    "signed_response_bytes": response["kie_response_bytes"],
                                }
                            else:
                                s = states[n]
                                s["age"] += 1
                                s["selected"] = 0
                                obtained[n] = {"kie_queried": 0, "kie_valid": 0,
                                               "kie_gap_full": "",
                                               "kie_rtt_ms": "",
                                               "signed_request_bytes": 0,
                                               "signed_response_bytes": 0}
                        for n in NODES:
                            out = obtained[n]
                            writer.writerow({
                                "trial": trial, "policy": policy, "tick": tick,
                                "node": n, "label": int(n in present),
                                "sba_up": current_sba[n]["up"],
                                "sba_rtt_ms": current_sba[n]["rtt_ms"],
                                **out, "kie_age": states[n]["age"],
                                "alarm": int(states[n]["gap"] > 0),
                                "risk_before": risks[n] if risks else "",
                                "provenance": PROVENANCE,
                            })
                        handle.flush()
                        time.sleep(interval)
                    # Start next trial with no active intervention.
                    active_spoof = set_switches(
                        active_spoof, set(), "kie-spoof-counter-only")
                    active_delay = set_switches(
                        active_delay, set(), "kie-delay-only")
    finally:
        # Remove all known agents' test flags irrespective of previous
        # exception, do not silently leave the next campaign poisoned.
        for n in NODES:
            try:
                docker("exec", f"kie8-{n}", "rm", "-f",
                       "/tmp/kie-spoof-counter-only", "/tmp/kie-delay-only")
            except Exception:
                pass
    report = {
        "provenance": PROVENANCE,
        "source": "actual eight HMAC-verified NF-colocated LAB agents and eight real HTTP2 NF listeners",
        "NF_internal_counter_provenance": "NOT native Open5GS counters",
        "fault": "artificially staged, GRAPH-CORRELATED counter-only signer dishonesty; NFs stay intact",
        "labels_used_by_online_ranking": False,
        "reported_target_plan_is_not_an_input_feature": True,
        "ticks_per_trial": TICKS, "trials": trials, "policy_order": order,
        "budget_after_tick_zero": {p: len(NODES) if p == "full" else BUDGET
                                   for p in policies},
        "selection_initialization": "all eight authenticated once at tick 0 per policy trial",
        "sent_authenticated_kie_calls": counts,
        "interventions": interventions,
        "source_commit": os.environ.get("GITHUB_SHA", "local"),
        "bayesian_model": str(bayes_model) if bayes_model else None,
        "bayesian_semantics": "approximate one-step POMDP, frozen prior historical FULL real KIE" if bayes_model else None,
    }
    output.with_suffix(".metadata.json").write_text(json.dumps(report, indent=2))
    return report


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--policies", nargs="+", required=True,
                   choices=SUPPORTED_POLICIES)
    p.add_argument("--trials", type=int, default=2)
    p.add_argument("--seed", type=int, default=SCENARIO_SEED_TEST)
    p.add_argument("--model-root", type=Path)
    p.add_argument("--bayes-model", type=Path)
    p.add_argument("--interval", type=float, default=.08)
    a = p.parse_args()
    print(json.dumps(acquire(a.output, tuple(a.policies),
                             a.trials, a.seed, a.model_root, a.interval, a.bayes_model),
                     indent=2))


if __name__ == "__main__":
    main()
