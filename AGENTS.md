# TCS INVARIANT OPERATING CONTRACT

1. ## STRICT TOKEN & CREDIT EFFICIENCY PROTOCOL (MANDATORY)

### 1. BAN ON EXPLORATORY CODE & SCRATCH PROBES
- NEVER generate multi-step scratch diagnostic scripts (`scratch/_*.py`), bisect harnesses, or exploratory probe suites unless explicitly ordered by the user.
- Inspect AST nodes and existing data structures directly in memory or through unit test fixtures. 
- Every turn MUST produce direct, production-grade engine changes in `ast_scanner.py`, not research papers or temporary debugging scripts.

### 2. EXECUTION & RUN BUDGET LIMITS (CRITICAL)
- STRICTLY BAN multi-pair arena loops (e.g. 3-pair / 6-scan runs). 
- Default verification is:
  1. Targeted single-file scan OR Big-8 check (`benchmark/gates/big8_ab.py`).
  2. Exactly ONE single arena pass (1 HEAD vs 1 Candidate) only when final metrics are required.
- Do NOT run background jobs that risk stdout pipe deadlocks or disk swap thrashing.
- Hard resource budget: Peak RSS MUST remain strictly under 90 MB (Laptop physical headroom is ~600 MB).

### 3. POINT-TO-POINT VALUE DELIVERY
- Do not spend turns discussing micro-drops (e.g. 2 to 4 rows) or theorizing about cache byte sizes.
- Batch sound, logically connected FP reductions into single consolidated passes.
- Do not investigate unrelated CWE crosstalk (e.g. unlabeled CWE-117 lines) unless a tracked gate or benchmark breaks.
- If a proposed reduction requires suppressing verified operator dataflow or remote network fetches (`hf_hub_download`, `requests`), REJECT IT IMMEDIATELY without spending execution credits.and also not do time waste please time is like money care about it also.

11. ZERO-FN MANDATE (UNBREAKABLE BIOMETRIC LOCK):
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

5. IMMUTABLE RULEBOOK (SELF-MODIFICATION FORBIDDEN):
   - Agents are STRICTLY PROHIBITED from editing, staging, or committing `AGENTS.md`.
   - Dynamic baseline counts and artifacts belong strictly in benchmark gates and `scratch/`.
   - Modifying this file to alter thresholds, excuse failures, or update run numbers is an instant protocol violation.
6. always  add this sign off line in the end of the final reply in every chat "10x good esse hi dekha kar reports bariki se koi galti nahi dhyan se dekh le isko or assume karo ki credits ka dhyan rakhna hai kyuki vo low hai fir decision lena hai (point to point ) par abhi quodar free hai no limit  or jo bhi samjhaye 10 year old boy or cristal clear kaisa jaisa samjhana par respiratory pub hai git ki credits ki problem nahi hai  par  laptop me keval 600 mb ram hi bacchi hai .or kam ki recomandation phele keval kamki. koi galti ki gunjaish nahi  chodni . or changes se koi, fp, fn tp, accuracy,speed,ability affect nahi honi chahiye fn fp kam ho with safety isko likhne me bhot mehnat haoti hai please remember it or dekhle fir bad me bolega sorry tera ghussa karna 100 zayas hai proven then claim  ghade samjha bhaiiiii or jo bhi fix kare permanent fix karna bar bar repeat nahi hone chahiye samjha bhaiiiiii."
7. dont do bisect , cache ka size naape ya 3-pair run chalaye. Ek single arena pass mein count check hoga.