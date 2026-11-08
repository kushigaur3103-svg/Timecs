# TCS INVARIANT OPERATING CONTRACT

1. ZERO-FN MANDATE (UNBREAKABLE BIOMETRIC LOCK):
   - `python benchmark/gates/big8_ab.py` MUST be 119/119 (MISSING=0, NEW=0).
   - `python benchmark/gates/aa_parity.py` MUST be 425/425 (MISSING=0, NEW=0).
   - `python benchmark/cross_runner.py` MUST maintain F1=1.0000.
   - Any dropped blessed key causes immediate hard rollback.

2. MANDATORY ACTIVE PARTITIONING (THE ANTI-SURRENDER LAW):
   - Blank punts, task abandonment, or keeping an entire cluster loud due to partial TP overlap is STRICTLY FORBIDDEN.
   - PROTOCOL: If an AST pattern matches N candidate rows, and K rows (where K >= 1) overlap with blessed TPs:
     1. You MUST explicitly isolate and pin those exact K nodes LOUD via fail-closed guard or exact AST identity (`KEEP_LOUD_EXCEPTION`).
     2. You MUST suppress the remaining (N - K) verified safe rows in the EXACT SAME TURN AND COMMIT.
   - Walking away from the (N - K) clean rows under "TP risk" is classified as a protocol failure.

3. MONOTONIC FP REDUCTION (NO HEURISTIC SHORTCUTS):
   - Total Arena findings count MUST remain strictly <= 1,602.
   - Path/folder blacklisting (`tests/`, `examples/`, `docs/`) is permanently prohibited.
   - Suppressions must be proven via AST-level dataflow, argument types, or provenance only.

4. HARD RESOURCE & PERFORMANCE CEILINGS:
   - Peak RSS memory MUST remain strictly under 90 MB.
   - Scan latency ratio MUST remain <= 1.0x vs HEAD (zero performance regression).
   - All 36 tracked gates in `scratch/run_all_gates.py` MUST pass (36/36).
