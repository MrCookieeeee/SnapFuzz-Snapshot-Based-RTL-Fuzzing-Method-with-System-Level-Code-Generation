"""Instruction rebalancing from Algorithm 1 of the SnapFuzz paper."""

from generation.Instructions import (
    ISAInstClass_Initial_Boosters, Instr_Groups, Instr_Mapping,
)


BETA = 2.0
GAMMA = 0.5
LAMBDA_EMA = 0.3
EPSILON = 0.01
S_MIN = 0.01
MAX_CATEGORY_WEIGHT = 0.30
EPOCH_INSTRUCTIONS = 250
MAX_EPOCH_INSTRUCTIONS = 100_000

DIRECT_CATEGORIES = (
    "ALU", "MULDIV", "BRANCH", "MEM", "FPU", "CSR", "EXCEPTION",
)

# Retain the existing influence map for the paper's four indirect categories.
PROXY_MAP = {
    "ICACHE": {"BRANCH": 0.4, "MEM": 0.3, "ALU": 0.1},
    "INTERCONNECT": {"MEM": 0.7, "EXCEPTION": 0.3},
    "CORE": {"ALU": 0.2, "BRANCH": 0.2, "MEM": 0.2,
             "CSR": 0.2, "EXCEPTION": 0.2},
    "INTERRUPT": {"CSR": 0.6, "EXCEPTION": 0.4},
}

_GROUP_CLASSES = {
    category: tuple(Instr_Mapping[name] for name in Instr_Groups[category])
    for category in DIRECT_CATEGORIES
}


def apply_category_weights(category_weights, instr_prob):
    """Return new class weights, preserving within-group ratios and zeros.

    Keep the total weight assigned to the seven direct categories unchanged,
    so other classes, including SFENCE_VMA, retain their original weight.
    """
    result = dict(instr_prob)
    group_totals = {
        category: sum(instr_prob[cls] for cls in classes)
        for category, classes in _GROUP_CLASSES.items()
    }
    direct_total = sum(group_totals.values())
    for category, classes in _GROUP_CLASSES.items():
        if group_totals[category] == 0:
            continue
        scale = category_weights[category] * direct_total / group_totals[category]
        for cls in classes:
            result[cls] = instr_prob[cls] * scale
    return result


class CYWRRebalancer:
    """Keep cumulative coverage snapshots and update instruction weights."""

    def __init__(self, initial_instr_prob=None):
        self._initial_instr_prob = dict(
            ISAInstClass_Initial_Boosters
            if initial_instr_prob is None else initial_instr_prob
        )
        group_totals = {
            category: sum(self._initial_instr_prob[cls] for cls in classes)
            for category, classes in _GROUP_CLASSES.items()
        }
        total = sum(group_totals.values())
        if total <= 0:
            raise ValueError("Instruction weights must have positive total weight")
        self._weights = {category: weight / total
                         for category, weight in group_totals.items()}
        self._prev_ratios = None
        self._pending_instructions = 0
        self._epoch_instructions = EPOCH_INSTRUCTIONS

    @property
    def epoch_instructions(self):
        return self._epoch_instructions

    @property
    def category_weights(self):
        return dict(self._weights)

    def update(self, curr_ratios, epoch_instructions):
        """Return new class weights once an instruction epoch is complete.

        Ratios are cumulative covered/total values. Missing categories have
        no measured coverage points and are treated as saturated.
        ``epoch_instructions`` counts instructions since the previous call.
        Return None for the first baseline and for incomplete epochs.
        """
        ratios = {
            category: curr_ratios.get(category, 1.0)
            for category in (*DIRECT_CATEGORIES, *PROXY_MAP)
        }
        if self._prev_ratios is None:
            self._prev_ratios = ratios
            return None
        if epoch_instructions <= 0:
            raise ValueError("A rebalancing epoch must contain instructions")
        self._pending_instructions += epoch_instructions
        if self._pending_instructions < self._epoch_instructions:
            return None
        epoch_instructions = self._pending_instructions

        gaps = {category: 1.0 - ratio for category, ratio in ratios.items()}
        deltas = {
            category: ratios[category] - self._prev_ratios[category]
            for category in DIRECT_CATEGORIES
        }
        yields = {}
        for category in DIRECT_CATEGORIES:
            allocated = self._weights[category] * epoch_instructions
            yields[category] = max(deltas[category], 0.0) / allocated if allocated else 0.0
        max_yield = max(yields.values())

        scores = {}
        for category in DIRECT_CATEGORIES:
            # Compare ratios to avoid 1 - 0.99 falling just above epsilon.
            if ratios[category] >= 1.0 - EPSILON:
                scores[category] = S_MIN
            else:
                normalized_yield = yields[category] / max_yield if max_yield else 0.0
                scores[category] = (gaps[category]
                                    + BETA * normalized_yield * gaps[category]
                                    + GAMMA * (deltas[category] == 0))

        for category, drivers in PROXY_MAP.items():
            if ratios[category] < 1.0 - EPSILON:
                for driver, influence in drivers.items():
                    scores[driver] += influence * gaps[category]

        score_total = sum(scores.values())
        weights = {
            category: min(MAX_CATEGORY_WEIGHT, max(
                S_MIN,
                (1.0 - LAMBDA_EMA) * self._weights[category]
                + LAMBDA_EMA * scores[category] / score_total,
            ))
            for category in DIRECT_CATEGORIES
        }
        total = sum(weights.values())
        self._weights = {category: weight / total
                         for category, weight in weights.items()}
        self._prev_ratios = ratios
        self._pending_instructions = 0
        self._epoch_instructions = min(MAX_EPOCH_INSTRUCTIONS, 2 * self._epoch_instructions)
        return apply_category_weights(self._weights, self._initial_instr_prob)
