"""Active-partitioning lock: the slices shipped under the updated Zero-FN Shield.

The mandate asked for three filters. Two of them already existed in the engine, so the work was to
find the population that is still loud, prove a value-domain slice that no blessed key shares, and
ship that slice -- not to re-add a rule that was already there. Everything below is measured on this
checkout, and every conjunct has a mutation that moves it.

Slice A -- CWE-22, a read-only open whose path is a compile-time string literal
------------------------------------------------------------------------------
`_sink_context_exempt` already exempted read-only opens inside a test tree (ast_scanner.py:7431-7452
before this change). The 35 arena sites that are still registered are the NON-test ones, so the new
proof carries no path test at all: a path written in the source text has no runtime component an
attacker could steer. The observable is `sink_records`, exactly as the mandate named it -- these rows
never reached a finding on either arm, so a finding count is the one instrument that cannot see the
win. Measured per fixture, CWE-22 records only:
    literal read 0, literal 'rb' 0, literal with a runtime mode 1, literal write 1, runtime read 1.
A mode that is not a literal stays registered: `open(p, mode_var)` could be 'w' at runtime, and the
default-is-read argument only applies when no mode was passed at all.

Slice B -- CWE-338, two value-domain proofs inside `_cwe338_display_only_draw`
----------------------------------------------------------------------------
The test-tree exemption (ast_scanner.py:7453-7465) already covers test files; the arena rows that
remain live in `src/` and `examples/`. Two shapes there are provably not credentials:
  * `random.uniform(0, 1)` -- two literal bounds, so the value domain is the closed unit interval.
    36 arena rows are exactly `dropout_probability = random.uniform(0, 1)`. The other three arena
    `uniform` rows carry runtime bounds and stay loud.
  * `for index in random.sample(range(len(dataset)), 3)` -- the population is a container's length,
    so the draw returns POSITIONS, and the loop consumes them as indices. 21 arena rows. A code or
    OTP generator draws from a literal alphabet (`range(10)`), never from a dataset's length, and
    that fixture stays loud.
Both proofs sit AFTER the credential and `.join` vetoes, so a security-named destination still wins.
0 of the 16 blessed CWE-338 keys is a `uniform` call or a `sample(range(len(...)))` loop.

The veto hole this exposed, and its measured-free fix
----------------------------------------------------
`random.sample(range(len(passwords)), 3)` was loud on HEAD and went quiet under the first draft of
Slice B: CWE338_SECURITY_NAME_WORDS carried a plural for every member of its family except `password`
and `seed`, and a container name is exactly where the plural appears. Adding `passwords` and `seeds`
restores the veto. Measured before adding: 0 arena CWE-338 rows and 0 of the 16 blessed keys contain
either word; the 20 `seeds` occurrences in the arena are comments plus one literal `SEEDS = [...]`
parametrisation list, never a draw destination. So the completion re-loudens nothing that is quiet.

Slice C -- CWE-208, the constant-integer partition is already shipped, and is defended twice
-------------------------------------------------------------------------------------------
`_compares_two_secrets` refuses any `ast.Constant` operand (ast_scanner.py:8561) and
`_c208_is_unit_test_assertion` refuses a test assertion without credential provenance
(ast_scanner.py:8512). Measured: 0 of the 118 arena CWE-208 rows is an equality against an integer
literal -- the only four rows with an int operand are a `< 1` tensor metric and three
`len(token_ids) > 0` guards beside `token_ids[-1] == self.eos_token_id`, which the mandate keeps loud.
So there is no new predicate here and nothing to suppress; what this gate adds is the lock, plus the
proof that the partition is load-bearing: blinding the Constant refusal alone already re-loudens a
credential-named `secret_size == 2`, blinding both guards keeps it loud, and `batch_size == 2` stays
quiet under both because the credential-name axis is a third, independent guard.

Slice D -- CWE-22, the path a hub cache resolver built is not a path the caller chose
-------------------------------------------------------------------------------------
`_c22_is_hub_cache_read` exempts an `open()` whose path argument IS the return value of
`hf_hub_download` / `cached_download`, in read mode, when the name is bound -- either the module
carries `from huggingface_hub import <name>`, or the call uses the qualified
`huggingface_hub.<name>` spelling. Three conjuncts, each with its own mutation:
  * the argument must be the resolver call itself: `os.path.join(root_dir, hf_hub_download(...))`
    is attacker-prefixed and stays loud, which is the fixture `resolver_join_prefix_stays_loud`;
  * a same-named local `def hf_hub_download` proves nothing, so `resolver_local_def_is_not_a_binding`
    stays loud -- the proof is the import, never the leaf spelling;
  * a non-literal or writing mode is unknown, so both stay registered.
Measured over the arena CI rows the current engine still emits: 52 rows in 48 converter scripts
match, and 0 of the 24 blessed CWE-22 keys (8 parity + 16 Big-8) match in any spelling.

Refused, with its numbers -- CWE-117, the numeric-format-spec proof
--------------------------------------------------------------------
`format(v, ",")` raises on a `str`, so an f-string field carrying a `,` (or `d`/`.3f`/`%`) spec is
CPython-proven numeric and cannot smuggle the newline CWE-117 is about. Elegant, and still wrong:
it yields 3 arena rows and, on the pinned Big-8 corpus, deletes 8 CWE-117 rows out of 29 --
1602/1603/1604/1605/1607/1608/1610/1611 in `src/transformers/trainer.py`, every one of them a blessed
key and not one an FP. Tier 8 pins all eight loud and the mutation installs the predicate to prove
the refusal is load-bearing.

Slice E -- CWE-22/770, the path a program's own command line chose is not a path a caller chose
----------------------------------------------------------------------------------------------
One blessed CWE-22 key can sit in the same origin class (`function_parameter`, 52 arena rows vs 3
blessed) as hundreds of false alarms, and the answer to that is not to leave the whole class loud:
it is to add the AST conditions that no blessed key satisfies. The condition here is a positive
presence proof, twice over -- the file BOTH parses its own command line (`parse_args`) AND runs under
`if __name__ == "__main__":`, and the `open()`'s path argument walks back to an argparse leaf with
nothing untrusted joined in. A library module has neither fact, so the same taint shape there stays
loud. Measured on the CI arena rows the engine still emitted: 14 rows match, all `models/*/convert_*`
checkpoint scripts, and the predicate silences all 14 at registration; over the whole arena this slice
alone removes 81 rows (1873 -> 1792) with 0 rows added -- the same 325 chunks with the proof blinded
emit 1873 rows in 219.79 s against 1792 rows in 204.39 s with it, so the walk costs nothing it does not
pay back. Muting a CWE-22 row un-masks the `f.read()` underneath it -- which is why the same proof is
wired into the CWE-770 unbounded-read branch too.

The trust is on the *binding*, never on the spelling of a variable, and that is what the last nine
fixtures pin. A name is resolved through the enclosing callables innermost-first, so a converter's
local `args = chkpt["cfg"]["model"]` may not poison the module's `args = parser.parse_args()` (the
arena's biogpt/fsmt/gptsan/megatron rows are exactly that shape), and equally the module's parse may
not vouch for a handler whose parameter merely shares the name, a loop target, a lambda argument, a
nested tuple rebind like `head, (args, tail) = split_request(body())`, or a field somebody wrote
into. A namespace handed to a function is still a namespace -- `convert(args)` stays quiet while
`convert(os.environ['P'])` and `args.dest = fetch_payload()` stay loud -- and a name called `argv`
that came off a socket proves nothing. Mutants M6/M7/M8 blind the binding proof, the scope split and
the write veto one at a time, and each moves only the fixtures that depend on it.

Reach on the baseline is 0, and tier 9 proves it without the corpus-name shield: the frozen keys live
under paths containing `src__`/`tests__`, and every CWE-22 exemption sits behind `not is_protected`,
so a green parity run says nothing about this predicate. Tier 9 reads the SAME bytes and scans them
under `vendor/...` keys, where the shield cannot help, and pins all 24 blessed CWE-22 lines loud.
Called directly, the predicate fires on 0 of the 19 `open()` nodes that sit on a blessed line; the
other 5 keys are `os.remove`/`shutil.rmtree`/`Path.read_bytes`/`.extract()` sinks, and forcing the
predicate True on them is the mutation that shows the tier can move.
"""
from __future__ import annotations

import ast
import contextlib
import io
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
GATES_DIR = os.path.join(ROOT, 'benchmark', 'gates')
BIG8_CORPUS = os.path.join(ROOT, 'benchmark_gates_data', 'corpus_big8')
CORPUS_DIR = os.path.join(ROOT, 'benchmark', 'corpus')
BENCHMARK_DIR = os.path.join(ROOT, 'benchmark')
MODELING_COMMON = 'tests__test_modeling_common.py'
GENERATION_UTILS = 'tests__generation__test_utils.py'
WHISPER = 'tests__models__whisper__test_modeling_whisper.py'

import cli  # noqa: E402
import ast_scanner  # noqa: E402


def scan(files: dict, cwe: str) -> tuple:
    """One in-process scan: (loud lines, registered sinks, sink_records) for one CWE."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files=files, max_workers=1)
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
        registered = sum(1 for sink in tracker.sinks if (sink.metadata or {}).get('cwe') == cwe)
        records = sum(1 for record in tracker.sink_records
                      if (record.security_node.metadata or {}).get('cwe') == cwe)
    loud = sorted(int(row['line']) for row in rows if row['cwe'] == cwe)
    return loud, registered, records


# Slice A fixtures: (source path, source, expected loud lines, expected CWE-22 sink_records).
C22_FIXTURES = {
    'literal_read': ('src/m.py',
                     "def f():\n"
                     + "    with open('vocab.json') as h:\n"
                     + "        return h.read()\n", [], 0),
    'literal_read_rb': ('src/m.py',
                        "def f():\n"
                        + "    with open('vocab.json', 'rb') as h:\n"
                        + "        return h.read()\n", [], 0),
    'literal_runtime_mode': ('src/m.py',
                             "def f(mode_var):\n"
                             + "    with open('vocab.json', mode_var) as h:\n"
                             + "        return h.read()\n", [], 1),
    'literal_write': ('src/m.py',
                      "def f():\n"
                      + "    with open('vocab.json', 'w') as h:\n"
                      + "        h.write('x')\n", [], 1),
    'runtime_read': ('src/m.py',
                     "def f(filename):\n"
                     + "    with open(filename) as h:\n"
                     + "        return h.read()\n"
                     # The argv read is the entrypoint fact that keeps this row loud now that the
                     # entrypoint guard declines synthetic sources in pure library modules; the
                     # literal-vs-runtime contrast below is still what this fixture measures.
                     + "import sys\n"
                     + "print(sys.argv[1])\n", [2], 1),
}

# Slice D fixtures: the hub cache-resolver origin proof. (path, source, loud lines, sink_records).
# Every quiet row must register nothing, and every veto row must still register and still shout.
C22_RESOLVER_FIXTURES = {
    'resolver_bare_import_read': ('src/convert_x_to_pytorch.py',
                                  "from huggingface_hub import hf_hub_download\n"
                                  + "def get_labels(repo_id, filename):\n"
                                  + "    with open(hf_hub_download(repo_id, filename), \"r\") as h:\n"
                                  + "        return h.read()\n"
                                  # Entrypoint fact so the two hub mutations below can still move this
                                  # row: with the proof blinded the sink registers, and only a module
                                  # that declares an entrypoint still reports an unproven open().
                                  + "import sys\n"
                                  + "print(sys.argv[1])\n", [], 0),
    'resolver_qualified_read': ('src/convert_x_to_pytorch.py',
                                "import huggingface_hub\n"
                                + "def get_labels(repo_id, filename):\n"
                                + "    with open(huggingface_hub.hf_hub_download(repo_id, filename)) as h:\n"
                                + "        return h.read()\n"
                                # Same entrypoint fact as the bare-import twin: this one must stay
                                # quiet when the binding table is blinded, because the qualified
                                # spelling is recognised without it.
                                + "import sys\n"
                                + "print(sys.argv[1])\n", [], 0),
    'resolver_cached_download_read': ('src/convert_x_to_pytorch.py',
                                      "from huggingface_hub import cached_download, hf_hub_url\n"
                                      + "def get_labels(repo_id, filename):\n"
                                      + "    with open(cached_download(hf_hub_url(repo_id, filename)), \"r\") as h:\n"
                                      + "        return h.read()\n", [], 0),
    'resolver_local_def_is_not_a_binding': ('src/convert_x_to_pytorch.py',
                                            "def hf_hub_download(repo, name):\n"
                                            + "    return repo\n"
                                            + "def get_labels(repo_id, filename):\n"
                                            + "    with open(hf_hub_download(repo_id, filename), \"r\") as h:\n"
                                            + "        return h.read()\n"
                                            # Entrypoint fact, so the local-def refusal is what keeps
                                            # this row loud rather than a module-level CLI declaration.
                                            + "import sys\n"
                                            + "print(sys.argv[1])\n", [4], 1),
    'resolver_join_prefix_stays_loud': ('src/convert_x_to_pytorch.py',
                                        "from huggingface_hub import hf_hub_download\n"
                                        + "import os\n"
                                        + "def get_labels(root_dir, repo_id, filename):\n"
                                        + "    with open(os.path.join(root_dir, hf_hub_download(repo_id, filename)), \"r\") as h:\n"
                                        + "        return h.read()\n"
                                        # Entrypoint fact: the open() taint requirement retires an
                                        # unproven open in a module that declares none, so the hub
                                        # refusal below needs a module where open() still reports.
                                        + "import sys\n"
                                        + "print(sys.argv[1])\n", [4], 1),
    'resolver_write_mode_stays_loud': ('src/convert_x_to_pytorch.py',
                                       "from huggingface_hub import hf_hub_download\n"
                                       + "def get_labels(repo_id, filename):\n"
                                       + "    with open(hf_hub_download(repo_id, filename), \"w\") as h:\n"
                                       + "        h.write(\"x\")\n"
                                       # Entrypoint fact, as above: the write-mode refusal is what
                                       # keeps this row loud, not the retired open() fallback.
                                       + "import sys\n"
                                       + "print(sys.argv[1])\n", [3], 1),
    'resolver_runtime_mode_stays_loud': ('src/convert_x_to_pytorch.py',
                                         "from huggingface_hub import hf_hub_download\n"
                                         + "def get_labels(repo_id, filename, stream_mode):\n"
                                         + "    with open(hf_hub_download(repo_id, filename), stream_mode) as h:\n"
                                         + "        return h.read()\n"
                                         # Entrypoint fact, as above: the runtime-mode refusal is what
                                         # keeps this row loud, not the retired open() fallback.
                                         + "import sys\n"
                                         + "print(sys.argv[1])\n", [3], 1),
}

# Slice E fixtures: the operator-program proof. Each entry is (path, source, CWE, loud lines,
# CWE sink_records) and every expectation is the number the working-copy engine printed for that
# exact string -- see scratch/_slice_e5.py. Quiet rows must register nothing new, loud rows must
# still register, and no expectation here is a wildcard.
OP_ARGV = ("import argparse\n"
           + "import os\n"
           + "import shutil\n"
           + "\n"
           + "parser = argparse.ArgumentParser()\n")
OP_WRITE = ("\n"
            + "\n"
            + "def convert(out_path):\n"
            + "    with open(out_path, 'w') as h:\n"
            + "        h.write('x')\n"
            + "\n")
OP_MAIN = ("\n"
           + "if __name__ == '__main__':\n"
           + "    args = parser.parse_args()\n")

C22_OPERATOR_FIXTURES = {
    # The two presence facts and a walkable chain: quiet.
    'operator_positional_call': ('src/m.py', OP_ARGV + OP_WRITE + OP_MAIN
                                 + "    convert(args.checkpoint)\n", 'CWE-22', [], 1),
    'operator_keyword_call': ('src/m.py', OP_ARGV + OP_WRITE + OP_MAIN
                              + "    convert(out_path=args.checkpoint)\n", 'CWE-22', [], 1),
    'operator_assigned_local': ('src/m.py', OP_ARGV + OP_WRITE + OP_MAIN
                                + "    path = args.checkpoint\n    convert(path)\n", 'CWE-22', [], 1),
    'operator_rmtree_built_dir': ('src/m.py', OP_ARGV
                                  + "\n\ndef convert(out_dir):\n"
                                  + "    tmp = os.path.join(out_dir, 'tmp')\n"
                                  + "    shutil.rmtree(tmp)\n"
                                  + "\n" + OP_MAIN + "    convert(args.model_dir)\n",
                                  'CWE-22', [], 1),
    # Every one of these is an absence or an unresolvable value: loud, and still registered.
    'no_main_guard_stays_loud': ('src/m.py', OP_ARGV + OP_WRITE
                                 + "\nargs = parser.parse_args()\nconvert(args.checkpoint)\n",
                                 'CWE-22', [9], 2),
    'uncalled_function_stays_loud': ('src/m.py', OP_ARGV + OP_WRITE + OP_MAIN, 'CWE-22', [9], 1),
    'unknown_call_stays_loud': ('src/m.py', OP_ARGV
                                + "\n\ndef convert(out_path):\n"
                                + "    with open(fetch_root(out_path), 'w') as h:\n"
                                + "        h.write('x')\n"
                                + "\n" + OP_MAIN + "    convert(args.checkpoint)\n",
                                'CWE-22', [9], 1),
    'unknown_wrap_stays_loud': ('src/m.py', OP_ARGV
                                + "\n\ndef convert(out_path):\n"
                                + "    with open(resolve(out_path), 'w') as h:\n"
                                + "        h.write('x')\n"
                                + "\n" + OP_MAIN + "    convert(args.checkpoint)\n",
                                'CWE-22', [9], 1),
    'unbound_wrapper_stays_loud': ('src/m.py', OP_ARGV
                                   + "\n\ndef convert(out_path):\n"
                                   + "    with open(removeprefix(out_path, \"pre\"), 'w') as h:\n"
                                   + "        h.write('x')\n"
                                   + "\n" + OP_MAIN + "    convert(args.checkpoint)\n",
                                   'CWE-22', [9], 1),
    'environ_value_stays_loud': ('src/m.py', OP_ARGV
                                 + "\ndef convert_gin(gin_file):\n"
                                 + "    with open(gin_file, 'r') as f:\n"
                                 + "        raw = f.read()\n    return raw\n"
                                 + "\n\ndef run():\n    convert_gin(os.environ.get('GIN_FILE'))\n"
                                 + "\n" + OP_MAIN + "    run()\n", 'CWE-22', [8, 14], 2),
    'splat_call_stays_loud': ('src/m.py', OP_ARGV + OP_WRITE + OP_MAIN
                              + "    opts = {'out_path': args.checkpoint}\n    convert(**opts)\n",
                              'CWE-22', [9], 2),
    'environ_rmtree_stays_loud': ('src/m.py', OP_ARGV
                                  + "\ndef convert(out_dir):\n"
                                  + "    tmp = os.path.join(out_dir, 'tmp')\n"
                                  + "    shutil.rmtree(tmp)\n"
                                  + "\n\ndef run():\n    convert(os.environ.get('D'))\n"
                                  + "\n" + OP_MAIN + "    run()\n", 'CWE-22', [9], 1),
    # The holder has to still be a parsed command line in the scope that reads it. Each row below is
    # a way the trust could be borrowed without being earned, and the last two are the shapes the CI
    # arena's converter scripts actually use, so they must stay quiet for the right reason.
    'holder_rebound_stays_loud': ('src/m.py', OP_ARGV + OP_WRITE
                                  + "\nargs = parser.parse_args()\nargs = fetch_from_socket()\n"
                                  + "convert(args.dest)\n" + OP_MAIN, 'CWE-22', [9, 15], 2),
    'holder_is_param_stays_loud': ('src/m.py', OP_ARGV
                                   + "\nargs = parser.parse_args()\n\n\ndef convert(args):\n"
                                   + "    with open(args.dest, 'w') as h:\n        h.write('x')\n"
                                   + "\n\nconvert(os.environ['P'])\n" + OP_MAIN, 'CWE-22', [11], 1),
    'holder_field_written_stays_loud': ('src/m.py', OP_ARGV
                                        + "\nargs = parser.parse_args()\n"
                                        + "args.dest = fetch_payload()\n"
                                        + "with open(args.dest, 'w') as h:\n    h.write('x')\n"
                                        + OP_MAIN, 'CWE-22', [9], 1),
    'loop_target_shadows_stays_loud': ('src/m.py', OP_ARGV
                                       + "\nargs = parser.parse_args()\n"
                                       + "for args in scan_roots():\n"
                                       + "    with open(args.dest, 'w') as h:\n        h.write('x')\n"
                                       + OP_MAIN, 'CWE-22', [9], 1),
    'lambda_param_shadows_stays_loud': ('src/m.py', OP_ARGV
                                        + "\nargs = parser.parse_args()\n"
                                        + "write = lambda args: open(args.dest, 'w')\n"
                                        + OP_MAIN, 'CWE-22', [8], 1),
    'nested_tuple_rebind_stays_loud': ('src/m.py', OP_ARGV
                                       + "\nargs = parser.parse_args()\n"
                                       + "head, (args, tail) = split_request(body())\n"
                                       + "with open(args.dest, 'w') as h:\n    h.write('x')\n"
                                       + OP_MAIN, 'CWE-22', [9], 1),
    'argv_from_socket_stays_loud': ('src/m.py', OP_ARGV
                                    + "\nargv = read_socket()\n"
                                    + "with open(argv.out, 'w') as h:\n    h.write('x')\n"
                                    + OP_MAIN, 'CWE-22', [8], 1),
    'namespace_handoff_quiet': ('src/m.py', OP_ARGV
                                + "\nargs = parser.parse_args()\n\n\ndef convert(args):\n"
                                + "    with open(args.dest, 'w') as h:\n        h.write('x')\n"
                                + "\n\nconvert(args)\n" + OP_MAIN, 'CWE-22', [], 0),
    'other_scope_local_quiet': ('src/m.py', OP_ARGV + OP_WRITE
                                + "\n\ndef peek(chkpt):\n    args = chkpt[\"cfg\"]\n"
                                + "    return args\n" + OP_MAIN + "    convert(args.checkpoint)\n",
                                'CWE-22', [], 1),
}

# The `f.read()` under a muted operator-program open(): the CWE-22 row is gone, so the unbounded
# read is only quiet because the same proof is wired into the CWE-770 branch.
C770_OPERATOR_READ = ('src/m.py',
                      "import argparse\n"
                      + "import os\n"
                      + "import regex as re\n"
                      + "import shutil\n"
                      + "\n"
                      + "parser = argparse.ArgumentParser()\n"
                      + "\n\ndef convert_gin(gin_file):\n"
                      + "    with open(gin_file, 'r') as f:\n"
                      + "        raw = f.read()\n"
                      + "    return re.findall(r'(.*) = ([0-9.]*)', raw)\n"
                      + "\n" + OP_MAIN + "    convert_gin(args.gin_file)\n",
                      'CWE-770', [], 0)

# Slice F: the same two presence facts, applied to CWE-117. Every fixture is a HYBRID module -- it
# parses its own command line under `if __name__ == '__main__':` and also holds a `request`-shaped
# client value, because a log call only registers when the file has real client data somewhere. The
# client line (12) is therefore loud in all of them; what the slice decides is only the second line.
# Expectations are the numbers the working-copy engine printed for these exact strings.
C117_HEAD = ("import argparse\n"
             + "import logging\n"
             + "import os\n"
             + "import sys\n"
             + "\n"
             + "logger = logging.getLogger(__name__)\n"
             + "parser = argparse.ArgumentParser()\n")
C117_CLIENT = ("\n"
               + "\ndef handle(request):\n"
               + "    payload = request.args.get('q')\n"
               + "    logger.info(f'query = {payload}')\n")
C117_MAIN = ("\n"
             + "if __name__ == '__main__':\n"
             + "    args = parser.parse_args()\n")
C117_JSON_ARGV_MAIN = ("\n"
                       + "if __name__ == '__main__':\n"
                       + "    args = parser.parse_json_file(json_file=os.path.abspath(sys.argv[1]))\n")
C117_JSON_UNKNOWN_MAIN = ("\n"
                          + "if __name__ == '__main__':\n"
                          + "    args = parser.parse_json_file(json_file=fetch_path())\n")


def c117_case(body, main=C117_MAIN, head=C117_HEAD):
    return head + C117_CLIENT + body + main


C117_OPERATOR_FIXTURES = {
    # The logged text is this program's own argv, or a value CPython forces to have no line break.
    'argv_field_quiet': ('src/m.py', c117_case(
        "\n\ndef show():\n    logger.info(f'root = {args.model_dir}')\n"),
        'CWE-117', [12], 1),
    'numeric_local_quiet': ('src/m.py', c117_case(
        "\n\ndef report():\n    total = len(items) * 2\n"
        + "    logger.info(f'total = {total}')\n"),
        'CWE-117', [12], 1),
    'sealed_builtin_quiet': ('src/m.py', c117_case(
        "\n\ndef report(request_count):\n    logger.info(f'n = {len(request_count)}')\n"),
        'CWE-117', [12], 1),
    'json_config_from_argv_quiet': ('src/m.py', c117_case(
        "\n\ndef show():\n    logger.info(f'cfg = {args.train_file}')\n",
        main=C117_JSON_ARGV_MAIN),
        'CWE-117', [12], 1),
    # One unprovable field in the line and the whole line is reported again: the rule is every value,
    # not any value, and `str()`/a client payload/rebinding refuse.
    'client_text_stays_loud': ('src/m.py', c117_case(
        "\n\ndef other(request):\n    logger.info(f'e = {request.headers}')\n"),
        'CWE-117', [12, 16], 2),
    'mixed_client_and_argv_stays_loud': ('src/m.py', c117_case(
        "\n\ndef show():\n    logger.info(f'mix = {args.model_dir} {query}')\n"),
        'CWE-117', [12, 16], 2),
    'rebound_client_stays_loud': ('src/m.py', c117_case(
        "\n\ndef report():\n    total = len(items) * 2\n    total = query\n"
        + "    logger.info(f'total = {total}')\n"),
        'CWE-117', [12, 18], 2),
    # The newline-in-a-literal refusal and the shadowed-builtin refusal are predicate-level facts: a
    # log line whose only unproven value is a literal cannot register a CWE-117 sink at all (measured
    # 1 record, [12] loud), so pinning them as sink fixtures would be vacuous. They live in
    # C117_VALUE_PROOFS below, which asks `_c22_value_is_newline_free` the question directly.
    # A config file is only as trusted as the path it was read from.
    'json_config_from_unknown_stays_loud': ('src/m.py', c117_case(
        "\n\ndef show():\n    logger.info(f'cfg = {args.train_file}')\n",
        main=C117_JSON_UNKNOWN_MAIN),
        'CWE-117', [12, 16], 2),
    # Two functions that spell the same local the same way are two different proofs: the small one
    # binds an arithmetic value, the big one binds the request, and the value cache has to answer each
    # occurrence on its own.
    'same_name_two_scopes_split': ('src/m.py', c117_case(
        "\n\ndef small():\n    total = len(items) * 2\n"
        + "    logger.info(f'total = {total}')\n"
        + "\n\ndef big(request):\n    total = request.headers\n"
        + "    logger.info(f'total = {total}')\n"),
        'CWE-117', [12, 22], 2),
    # And a module that does not both parse its own command line and run as a program keeps all of it.
    'no_main_guard_stays_loud': ('src/m.py', c117_case(
        "\n\ndef report():\n    total = len(items) * 2\n"
        + "    logger.info(f'total = {total}')\n", main="\n\nreport()\n"),
        'CWE-117', [12, 17], 2),
    'no_parse_stays_loud': ('src/m.py', C117_HEAD.replace(
        "parser = argparse.ArgumentParser()\n", "") + C117_CLIENT
        + "\n\ndef report():\n    total = len(items) * 2\n"
        + "    logger.info(f'total = {total}')\n"
        + "\nif __name__ == '__main__':\n    report()\n",
        'CWE-117', [11, 16], 2),
}

# Tier 9: the frozen blessed CWE-22 keys, scanned under a key that the engine's corpus-name shield
# cannot see (`src__`/`tests__`/`corpus_big8`/`_p3_big` all make every CWE-22 exemption inert, so a
# green parity run is not the reach proof). Lines are the keys themselves, from the frozen .keys.
BLESSED_C22_REACH = {
    'src__transformers__modeling_utils.py': ('vendor/transformers/modeling_utils.py',
                                             (336, 3494, 3564)),
    'src__transformers__trainer.py': ('vendor/transformers/trainer.py', (2008, 4301)),
    'tests__generation__test_utils.py': ('vendor/generation/test_utils.py', (5537, 5539, 5565)),
    'tests__models__markuplm__test_tokenization_markuplm.py': ('vendor/markuplm/tok.py',
                                                               (73, 75, 77, 138)),
    'tests__test_modeling_common.py': ('vendor/base/modeling_common.py', (1279,)),
    'tests__test_tokenization_mistral_common.py': ('vendor/mistral/tok.py', (263, 274, 280)),
    'cwe_22_traversal/bad.py': ('vendor/trav/bad.py', (5,)),
    'cwe_22_traversal/test_v01_bad.py': ('vendor/trav/v01.py', (5,)),
    'cwe_22_traversal/test_v02_bad.py': ('vendor/trav/v02.py', (8,)),
    'cwe_22_traversal/test_v03_bad.py': ('vendor/trav/v03.py', (5,)),
    'cwe_22_traversal/test_v05_bad.py': ('vendor/trav/v05.py', (8,)),
    'cwe_937_insecure_protocol/test_v06_bad.py': ('vendor/proto/v06bad.py', (6,)),
    'cwe_937_insecure_protocol/test_v06_good.py': ('vendor/proto/v06good.py', (7,)),
    'runner.py': ('vendor/runner.py', (105,)),
}
# The single line tier 10's forced-True mutant must silence, and the file it is read from.
REACH_MUTATION_LEAF = 'tests__test_modeling_common.py'
REACH_MUTATION_KEY = 'vendor/base/modeling_common.py'
REACH_MUTATION_LINE = 1279

UNIFORM_UNIT = ("import random\n"
                + "class A:\n"
                + "    def __call__(self, hidden_states, deterministic=True):\n"
                + "        dropout_probability = random.uniform(0, 1)\n"
                + "        if not deterministic and dropout_probability < self.dropout:\n"
                + "            hidden_states = dropout(hidden_states)\n"
                + "        return hidden_states\n")
SAMPLE_INDEX = ("import random\n"
                + "def log_examples(train_dataset, logger):\n"
                + "    for index in random.sample(range(len(train_dataset)), 3):\n"
                + "        logger.info(train_dataset[index])\n")

# Slice B fixtures: (path, source, expected loud lines). Quiet rows must also register no sink.
C338_FIXTURES = {
    'uniform_unit_quiet': ('src/transformers/models/m.py', UNIFORM_UNIT, []),
    'sample_index_quiet': ('examples/run_qa.py', SAMPLE_INDEX, []),
    'uniform_runtime_bounds_loud': ('src/m.py',
                                    "import random\n"
                                    + "def f(self):\n"
                                    + "    aspect = random.uniform(self.lo, self.hi)\n"
                                    + "    return aspect\n", [3]),
    'sample_literal_alphabet_loud': ('src/m.py',
                                     "import random\n"
                                     + "def f():\n"
                                     + "    for i in random.sample(range(10), 6):\n"
                                     + "        print(i)\n", [3]),
    'uniform_credential_veto_loud': ('src/m.py',
                                     "import random\n"
                                     + "def f():\n"
                                     + "    secrets = random.uniform(0, 1)\n"
                                     + "    return secrets\n", [3]),
    'sample_passwords_veto_loud': ('examples/m.py',
                                   "import random\n"
                                   + "def f(passwords):\n"
                                   + "    for index in random.sample(range(len(passwords)), 3):\n"
                                   + "        print(index)\n", [3]),
    'sample_seeds_veto_loud': ('examples/m.py',
                               "import random\n"
                               + "def f(seeds):\n"
                               + "    for index in random.sample(range(len(seeds)), 3):\n"
                               + "        print(index)\n", [3]),
    'blessed_scale_loud': ('tests/test_modeling_common.py',
                           "def f(rng, values, scale):\n"
                           + "    values.append(rng.random() * scale)\n", [2]),
    'blessed_vocab_loud': ('tests/test_modeling_common.py',
                           "def f(rng, values, vocab_size):\n"
                           + "    values.append(rng.randint(0, vocab_size - 1))\n", [2]),
}

# Slice C fixtures: the partition is pre-existing, so these pin behaviour rather than a new predicate.
C208_FIXTURES = {
    'test_credential_int_quiet': ('tests/test_m.py',
                                  "def f(secret_size):\n"
                                  + "    assert secret_size == 2\n", []),
    'test_plain_int_quiet': ('tests/test_m.py',
                             "import unittest\n"
                             + "class T(unittest.TestCase):\n"
                             + "    def test_a(self):\n"
                             + "        batch_size = 2\n"
                             + "        assert batch_size == 2\n", []),
    'token_constant_loud': ('src/m.py',
                            "def f(input_ids, bos_token_id):\n"
                            + "    if input_ids == bos_token_id:\n"
                            + "        return 1\n", [2]),
}


def check_baseline_domain() -> list:
    """Only the two frozen key files are read here, each with its join written at the open site.

    Opening a per-key corpus path from a loop variable is itself a variable-derived path, and the
    engine reports it -- that is how an earlier draft of this gate added a NEW parity key. The
    behavioural half of the domain proof lives in check_blessed_lines_stay_loud instead.
    """
    failures = []
    expected = {'parity_before.keys': (425, 9), 'big8_before.keys': (119, 7)}
    for keys_name, (total_rows, c338_rows) in expected.items():
        with open(os.path.join(GATES_DIR, keys_name), encoding='utf-8') as handle:
            text = handle.read()
        rows = []
        for line in text.splitlines():
            entry = line.strip()
            if entry.startswith('('):
                row = ast.literal_eval(entry)
                if len(row) >= 3:
                    rows.append(row)
                    if row[2] == 'CWE-338':
                        c338_rows -= 1
        if len(rows) != total_rows:
            failures.append(f'{keys_name}: {len(rows)} keys, expected {total_rows}')
        if c338_rows:
            failures.append(f'{keys_name}: the CWE-338 key census moved, so the value-domain proof '
                            'is no longer over the frozen baseline')
        print(f'  tier1 {keys_name}: {len(rows)} keys, CWE-338 census intact')
    return failures


def check_slice_a() -> list:
    failures = []
    for name, (path, source, expected_loud, expected_records) in sorted(C22_FIXTURES.items()):
        loud, _registered, records = scan({path: source}, 'CWE-22')
        if loud != expected_loud:
            failures.append(f'{name}: CWE-22 lines {loud}, expected {expected_loud}')
        if records != expected_records:
            failures.append(f'{name}: {records} CWE-22 sink_records, expected {expected_records}; '
                            'the registration prune is the whole yield of this slice')
    print('  tier2 slice A fixtures checked:', len(C22_FIXTURES))
    return failures


def check_slice_b() -> list:
    failures = []
    for name, (path, source, expected) in sorted(C338_FIXTURES.items()):
        loud, registered, _records = scan({path: source}, 'CWE-338')
        if loud != expected:
            failures.append(f'{name}: CWE-338 lines {loud}, expected {expected}')
        if expected and not registered:
            failures.append(f'{name}: reported but no sink registered, so the census is not the '
                            'census being asserted')
        if not expected and registered:
            failures.append(f'{name}: quiet but {registered} sink(s) still registered; the prune '
                            'moved back to emission and the cascade is paying for it again')
    print('  tier3 slice B fixtures checked:', len(C338_FIXTURES))
    return failures


def check_slice_c() -> list:
    failures = []
    for name, (path, source, expected) in sorted(C208_FIXTURES.items()):
        loud, _registered, _records = scan({path: source}, 'CWE-208')
        if loud != expected:
            failures.append(f'{name}: CWE-208 lines {loud}, expected {expected}')
    print('  tier4 slice C fixtures checked:', len(C208_FIXTURES))
    return failures


def check_slice_d() -> list:
    failures = []
    for name, (path, source, expected, expected_records) in sorted(C22_RESOLVER_FIXTURES.items()):
        loud, _registered, records = scan({path: source}, 'CWE-22')
        if loud != expected:
            failures.append(f'{name}: CWE-22 lines {loud}, expected {expected}')
        if records != expected_records:
            failures.append(f'{name}: CWE-22 sink_records {records}, expected {expected_records} '
                            '(the mandate is registration, not emission)')
    print('  tier5 slice D fixtures checked:', len(C22_RESOLVER_FIXTURES))
    return failures


TRAINER_LEAF = 'src__transformers__trainer.py'
TRAINER_KEY = 'scratch/_p3_big/' + TRAINER_LEAF
BLESSED_C117_TRAINER = (1602, 1603, 1604, 1605, 1607, 1608, 1610, 1611)
# Filled by the shipped arm below; the mutation compares against it instead of a hand-typed count.
SHIPPED_TRAINER_LOUD = []


def trainer_rows() -> list:
    """One scan of the corpus file the numeric-spec slice would hit, on the repo-relative key.

    Two halves are load-bearing and both were measured. The bytes come from the tracked corpus copy
    (`verify_corpus` hashes it against the pinned value and `scratch/_p3_big/` is git-ignored, so CI
    has nothing else to read -- here they are byte-identical, 233,460 bytes). The key is the baseline
    spelling: with an absolute key the same source yields 12 CWE-117 rows instead of 29 and loses
    blessed lines 1605 and 1607, because `scope_module`/`file_paths` resolve through the
    repo-relative POSIX spelling the frozen `.keys` files themselves use.
    """
    with open(os.path.join(BIG8_CORPUS, TRAINER_LEAF), encoding='utf-8', errors='replace') as handle:
        src = handle.read()
    return scan({TRAINER_KEY: src}, 'CWE-117')


def check_refused_value_slice() -> list:
    """The numeric-format-spec exemption was measured and refused; this tier keeps it refused.

    `format(value, ",")` raises on a `str`, so a `,`-spec field is CPython-proven numeric and
    cannot carry the newline CWE-117 is about. It is still the right answer nowhere: measured over
    the live arena rows it yields 3 rows, and on this corpus the same predicate deletes 8 of the 29
    CWE-117 rows -- all eight are blessed keys (1602, 1603, 1604, 1605, 1607, 1608, 1610, 1611, the
    memory-stat block of `src/transformers/trainer.py`) and not one of them is an FP. 3 FPs for 8
    TPs is the trade the doctrine forbids, so the predicate stays out of the engine and all eight
    rows must be reported.
    """
    failures = []
    global SHIPPED_TRAINER_LOUD
    loud, _registered, _records = trainer_rows()
    SHIPPED_TRAINER_LOUD = list(loud)
    for line in BLESSED_C117_TRAINER:
        if line not in loud:
            failures.append(f'trainer.py:{line} went silent; it is one of the 8 blessed CWE-117 keys '
                            'the numeric-format-spec refusal exists to protect')
    print('  tier8 refused value slice pinned: 8 blessed CWE-117 lines loud '
          f'({len(loud)} CWE-117 rows in the trainer corpus)')
    return failures


def check_slice_e() -> list:
    failures = []
    rows = dict(C22_OPERATOR_FIXTURES)
    rows['operator_program_read'] = C770_OPERATOR_READ
    for name, (path, source, cwe, expected, expected_records) in sorted(rows.items()):
        loud, _registered, records = scan({path: source}, cwe)
        if loud != expected:
            failures.append(f'{name}: {cwe} lines {loud}, expected {expected}')
        if records != expected_records:
            failures.append(f'{name}: {records} {cwe} sink_records, expected {expected_records} '
                            '(the mandate is registration, not emission)')
    print('  tier10 slice E fixtures checked:', len(rows))
    return failures


def newline_free_proof(source: str, hole: str):
    """Ask `_c22_value_is_newline_free` the question it answers, on one f-string hole."""
    tracker = ast_scanner.TaintTracker(files={'src/m.py': source}, max_workers=1)
    mod = next(iter(tracker.file_paths), None)
    tree = tracker.modules.get(mod)
    if tree is None:
        return None
    shadowed = tracker._shadowed_names_in_tree(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.FormattedValue) and ast.unparse(node.value) == hole:
            return tracker._c22_value_is_newline_free(tree, node.value, shadowed)
    return None


def bound_value_probe(source: str, expr: str, names: list) -> list:
    """Ask `_c22_bound_values` the same node under each spelling in `names`, answers unparsed.

    The scope cache keys on (expression, name), so the question this answers is whether the name half
    of that key is real: `args.model_dir` is one node, and the namespace proof and the value chain ask
    it about two different things.
    """
    tracker = ast_scanner.TaintTracker(files={'src/m.py': source}, max_workers=1)
    mod = next(iter(tracker.file_paths), None)
    tree = tracker.modules.get(mod)
    if tree is None:
        return []
    target = None
    for node in ast.walk(tree):
        if ast.unparse(node) == expr and isinstance(node, (ast.Attribute, ast.Name)):
            target = node
            break
    if target is None:
        return []
    out = []
    for name in names:
        found = tracker._c22_bound_values(tree, target, name)
        out.append(None if found is None
                   else tuple(ast.unparse(v) if v is not None else 'None' for v in found[1]))
    return out


# (name, module source, the f-string hole to prove, expectation). `LOG_HEAD` is a module that is NOT
# an operator program: these rows pin the value proof alone, exactly as the arm composes it.
C117_VALUE_PROOFS = (
    ('literal_with_line_break', C117_HEAD + "label = 'a\\nb'\n"
     + "logger.info(f'v = {label}')\n", 'label', False),
    ('literal_without_line_break', C117_HEAD + "label = 'a b'\n"
     + "logger.info(f'v = {label}')\n", 'label', True),
    ('arithmetic_over_sealed_builtin', C117_HEAD + "total = len(items) * 2\n"
     + "logger.info(f'v = {total}')\n", 'total', True),
    ('shadowed_builtin_is_not_sealed', C117_HEAD + "\ndef len(value):\n    return 'a\\nb'\n"
     + "total = len(items) * 2\nlogger.info(f'v = {total}')\n", 'total', False),
    ('comparison_yields_a_bool', C117_HEAD + "enabled = count == 2\n"
     + "logger.info(f'v = {enabled}')\n", 'enabled', True),
    ('attribute_type_is_unknown', C117_HEAD + "logger.info(f'v = {cfg.name}')\n", 'cfg.name', False),
    ('rebound_to_unknown', C117_HEAD + "total = len(items)\ntotal = fetch()\n"
     + "logger.info(f'v = {total}')\n", 'total', False),
)


def check_slice_f() -> list:
    failures = []
    for name, (path, source, cwe, expected, expected_records) in sorted(
            C117_OPERATOR_FIXTURES.items()):
        loud, registered, records = scan({path: source}, cwe)
        if loud != expected:
            failures.append(f'{name}: {cwe} lines {loud}, expected {expected}')
        if records != expected_records:
            failures.append(f'{name}: {records} {cwe} sink_records, expected {expected_records} '
                            f'(registered={registered}; the mandate is registration, not emission)')
    print('  tier11 slice F fixtures checked:', len(C117_OPERATOR_FIXTURES))
    proofs = 0
    for name, source, hole, expected in C117_VALUE_PROOFS:
        got = newline_free_proof(source, hole)
        proofs += 1
        if got is None:
            failures.append(f'{name}: no f-string hole {hole} reached the proof (harness defect)')
        elif got is not expected:
            failures.append(f'{name}: _c22_value_is_newline_free({hole}) = {got}, '
                            f'expected {expected}')
    print('  tier11 slice F value proofs checked:', proofs)
    return failures


def _reach_row(leaf: str, entry: tuple, src: str) -> list:
    """One blessed file, scanned under the key the corpus-name shield cannot see."""
    key, lines = entry
    loud, _registered, _records = scan({key: src}, 'CWE-22')
    gone = [line for line in lines if line not in loud]
    if gone:
        return [f'{leaf}:{gone} went silent under the non-corpus key {key}; the operator-program '
                'proof may only fire where a library module cannot be mistaken for a program, and '
                'a blessed key is a true positive']
    return []


def check_operator_reach() -> list:
    """All 24 blessed CWE-22 keys re-scanned where the corpus-name shield cannot protect them.

    Every CWE-22 exemption in `_sink_context_exempt` sits behind `not is_protected`, and the frozen
    keys live under names carrying `src__`/`tests__`/`corpus_big8`, so parity would stay green even
    if this predicate reached a true positive. These are the same bytes under `vendor/...` keys,
    where the shield is blind and the shape has to fail on its own merits. Each path is a literal
    join at its own `open`: a corpus path resolved from a loop variable is itself a variable-derived
    path, and the engine reports it -- that is how this tier gained a NEW parity key.
    """
    failures = []
    with open(os.path.join(BIG8_CORPUS, 'src__transformers__modeling_utils.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('src/transformers/modeling_utils.py',
                                   BLESSED_C22_REACH['src__transformers__modeling_utils.py'],
                                   handle.read()))
    with open(os.path.join(BIG8_CORPUS, 'src__transformers__trainer.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('src/transformers/trainer.py',
                                   BLESSED_C22_REACH['src__transformers__trainer.py'],
                                   handle.read()))
    with open(os.path.join(BIG8_CORPUS, 'tests__generation__test_utils.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('tests/generation/test_utils.py',
                                   BLESSED_C22_REACH['tests__generation__test_utils.py'],
                                   handle.read()))
    with open(os.path.join(BIG8_CORPUS, 'tests__models__markuplm__test_tokenization_markuplm.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('tests/models/markuplm/test_tokenization_markuplm.py',
                                   BLESSED_C22_REACH['tests__models__markuplm__test_tokenization_markuplm.py'],
                                   handle.read()))
    with open(os.path.join(BIG8_CORPUS, 'tests__test_modeling_common.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('tests/test_modeling_common.py',
                                   BLESSED_C22_REACH['tests__test_modeling_common.py'],
                                   handle.read()))
    with open(os.path.join(BIG8_CORPUS, 'tests__test_tokenization_mistral_common.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('tests/test_tokenization_mistral_common.py',
                                   BLESSED_C22_REACH['tests__test_tokenization_mistral_common.py'],
                                   handle.read()))
    with open(os.path.join(CORPUS_DIR, 'cwe_22_traversal/bad.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('cwe_22_traversal/bad.py',
                                   BLESSED_C22_REACH['cwe_22_traversal/bad.py'], handle.read()))
    with open(os.path.join(CORPUS_DIR, 'cwe_22_traversal/test_v01_bad.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('cwe_22_traversal/test_v01_bad.py',
                                   BLESSED_C22_REACH['cwe_22_traversal/test_v01_bad.py'],
                                   handle.read()))
    with open(os.path.join(CORPUS_DIR, 'cwe_22_traversal/test_v02_bad.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('cwe_22_traversal/test_v02_bad.py',
                                   BLESSED_C22_REACH['cwe_22_traversal/test_v02_bad.py'],
                                   handle.read()))
    with open(os.path.join(CORPUS_DIR, 'cwe_22_traversal/test_v03_bad.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('cwe_22_traversal/test_v03_bad.py',
                                   BLESSED_C22_REACH['cwe_22_traversal/test_v03_bad.py'],
                                   handle.read()))
    with open(os.path.join(CORPUS_DIR, 'cwe_22_traversal/test_v05_bad.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('cwe_22_traversal/test_v05_bad.py',
                                   BLESSED_C22_REACH['cwe_22_traversal/test_v05_bad.py'],
                                   handle.read()))
    with open(os.path.join(CORPUS_DIR, 'cwe_937_insecure_protocol/test_v06_bad.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('cwe_937_insecure_protocol/test_v06_bad.py',
                                   BLESSED_C22_REACH['cwe_937_insecure_protocol/test_v06_bad.py'],
                                   handle.read()))
    with open(os.path.join(CORPUS_DIR, 'cwe_937_insecure_protocol/test_v06_good.py'),
              encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('cwe_937_insecure_protocol/test_v06_good.py',
                                   BLESSED_C22_REACH['cwe_937_insecure_protocol/test_v06_good.py'],
                                   handle.read()))
    with open(os.path.join(BENCHMARK_DIR, 'runner.py'), encoding='utf-8', errors='replace') as handle:
        failures.extend(_reach_row('benchmark/runner.py', BLESSED_C22_REACH['runner.py'],
                                   handle.read()))
    total = sum(len(lines) for _key, lines in BLESSED_C22_REACH.values())
    if total != 24:
        failures.append(f'the reach tier pins {total} blessed CWE-22 keys, expected 24 -- a key was '
                        'added to or dropped from the frozen baseline without updating this table')
    print(f'  tier9 blessed CWE-22 keys loud with the corpus-name shield removed: {total}')
    return failures


def check_blessed_lines_stay_loud() -> list:
    """The blessed lines a widened value-domain proof could actually reach, re-scanned loud."""
    failures = []
    with open(os.path.join(BIG8_CORPUS, MODELING_COMMON), encoding='utf-8', errors='replace') as handle:
        common_src = handle.read()
    loud, _reg, _rec = scan({os.path.join(BIG8_CORPUS, MODELING_COMMON): common_src}, 'CWE-338')
    for line in (6606, 6698, 6722):
        if line not in loud:
            failures.append(f'{MODELING_COMMON}:{line} went silent; it is a blessed CWE-338 key')
    loud22, _r2, _c2 = scan({os.path.join(BIG8_CORPUS, MODELING_COMMON): common_src}, 'CWE-22')
    if 1279 not in loud22:
        failures.append(f'{MODELING_COMMON}:1279 went silent; the mandate names it as the read-only '
                        'test open that must stay loud, and its path is a runtime name')
    with open(os.path.join(BIG8_CORPUS, GENERATION_UTILS), encoding='utf-8', errors='replace') as handle:
        gen_src = handle.read()
    loud_gen, _rg, _rc = scan({os.path.join(BIG8_CORPUS, GENERATION_UTILS): gen_src}, 'CWE-338')
    for line in (3352, 3367, 3384):
        if line not in loud_gen:
            failures.append(f'{GENERATION_UTILS}:{line} went silent; it is a blessed CWE-338 key')
    with open(os.path.join(BIG8_CORPUS, WHISPER), encoding='utf-8', errors='replace') as handle:
        whisper_src = handle.read()
    loud_wh, _rw, _rcw = scan({os.path.join(BIG8_CORPUS, WHISPER): whisper_src}, 'CWE-338')
    if 97 not in loud_wh:
        failures.append(f'{WHISPER}:97 went silent; it is a blessed CWE-338 key')
    print('  tier6 blessed lines re-scanned loud: 8')
    return failures


def check_source_shape() -> list:
    failures = []
    with open(os.path.join(ROOT, 'ast_scanner.py'), encoding='utf-8') as handle:
        source = handle.read()
    spellings = ('def _c22_is_literal_readonly_open',
                     'def _c22_is_hub_cache_read',
                     'def _c22_is_operator_program_open',
                     'def _c22_path_is_operator_supplied',
                     'def _c770_read_comes_from_operator_program',
                     'CWE22_OPERATOR_PROGRAM_CALLS = frozenset',
                     'isinstance(a, ast.Starred) for a in site.args',
                     # The value chain resolves names through the scope that owns them, so the scope
                     # tables and the namespace proof have to stay in the engine.
                     'def _c22_target_names',
                     'def _c22_scope_binds',
                     'def _c22_bound_values',
                     'def _c22_is_namespace_root',
                     'if (owner, field) in mutated or ("", field) in mutated:',
                     'stack.append((child, owner if decorators and child in decorators else inner))',
                     # Slice F: the arm, the two proofs it composes, and the file-parser trust rule
                     # that only clears when the file argument itself is operator-supplied.
                     'def _cwe117_message_is_operator_sealed',
                     'def _c22_value_is_newline_free',
                     'def _cwe117_logged_values',
                     'def _c22_operator_facts_on',
                     'CWE22_OPERATOR_FILE_PARSERS = frozenset',
                     'CWE22_OPERATOR_ROOT_CALLS = CWE22_OPERATOR_PROGRAM_CALLS | CWE22_OPERATOR_FILE_PARSERS',
                     'or (tree is not None and self._cwe117_message_is_operator_sealed(',
                     'if self._cwe117_message_is_sealed(node, shadowed, tree):',
                     # The two caches are pure, so their keys are the whole contract: one answer per
                     # (tree, expression, name) and one verdict per (tree, log statement).
                     'def _c22_bound_values_on',
                     'key = (id(node), name)',
                     'cache = tree.__dict__.get("_c117_operator_sealed")',
                     'cache[id(node)] = verdict',
                     # The facts pass reads the module's own cached node list and is only entered when
                     # the source could hold either fact, so it never costs a second traversal.
                     'def _c22_operator_facts_build',
                     'def _module_text_for',
                     'CWE22_OPERATOR_FACT_TOKENS = ("__name__", "parse_")',
                     'if text and not all(tok in text for tok in CWE22_OPERATOR_FACT_TOKENS):',
                     'for n in self._module_nodes(tree):',
                     # Every address that can register the row has to ask the new proof.
                     'if not is_protected and self._c22_is_operator_program_open(node, mod_name):',
                     'if self._c22_is_operator_program_open(node, mod_name):',
                     'and not self._c22_is_operator_program_open(node, mod_name):',
                     'and not self._c22_path_is_operator_supplied(path_expr, mod_name):',
                     'and not self._c770_read_comes_from_operator_program(node, mod_name)',
                     'CWE22_HUB_CACHE_RESOLVERS = frozenset',
                     'leaf == "uniform" and len(node.args) == 2',
                     'loop.iter is node',
                     '"passwords", "seeds",')
    for spelling in spellings:
        if spelling not in source:
            failures.append(f'the shipped proof is gone from the engine: {spelling}')
    retired = ('_C338_BLESSED_LINES_SHIELD', '_C338_BLESSED_LINES', 'is_test_or_eval',
               # A file-wide name table cannot tell a converter's local from the module's command
               # line, so it must not come back: the scope-keyed table is the shipped proof.
               'def _c22_assign_map', 'argparse_names:\n                return True',
               # The collector consulted the seal without a tree, so the operator-program arm could
               # not reach the path that records most of the arena's log sinks.
               'if self._cwe117_message_is_sealed(node, shadowed):\n',
               # The facts pass once did its own whole-tree walk, so every module that ever logged
               # paid a traversal the collector had already done.
               'for n in ast.walk(tree):\n                if (isinstance(n, ast.If)')
    for marker in retired:
        if marker in source:
            failures.append(f'a retired name/line shield is back in the engine: {marker}')
    print(f'  tier7 source spellings checked: {len(spellings)} present, '
          f'{len(retired)} retired markers absent')
    return failures


def run_mutations() -> list:
    """Every conjunct must move under its own mutation, and the engine must come back identical."""
    results = []

    shipped_literal = ast_scanner.TaintTracker._c22_is_literal_readonly_open
    ast_scanner.TaintTracker._c22_is_literal_readonly_open = lambda self, node: False
    try:
        _loud, _reg, records = scan({'src/m.py': C22_FIXTURES['literal_read'][1]}, 'CWE-22')
        results.append(('c22_literal_proof_blinded', records == 1))
    finally:
        ast_scanner.TaintTracker._c22_is_literal_readonly_open = shipped_literal

    shipped_resolver = ast_scanner.TaintTracker._c22_is_hub_cache_read
    ast_scanner.TaintTracker._c22_is_hub_cache_read = lambda self, node, mod_name='': False
    try:
        loud, _reg, records = scan(
            {'src/convert_x_to_pytorch.py': C22_RESOLVER_FIXTURES['resolver_bare_import_read'][1]},
            'CWE-22')
        results.append(('c22_hub_resolver_proof_blinded', loud == [3] and records == 1))
    finally:
        ast_scanner.TaintTracker._c22_is_hub_cache_read = shipped_resolver

    shipped_bindings = ast_scanner.TaintTracker._c22_module_hub_resolvers
    ast_scanner.TaintTracker._c22_module_hub_resolvers = lambda self, mod_name: frozenset()
    try:
        loud_bare, _r1, _c1 = scan(
            {'src/convert_x_to_pytorch.py': C22_RESOLVER_FIXTURES['resolver_bare_import_read'][1]},
            'CWE-22')
        loud_qual, _r2, _c2 = scan(
            {'src/convert_x_to_pytorch.py': C22_RESOLVER_FIXTURES['resolver_qualified_read'][1]},
            'CWE-22')
        results.append(('c22_hub_import_binding_is_load_bearing',
                        loud_bare == [3] and loud_qual == []))
    finally:
        ast_scanner.TaintTracker._c22_module_hub_resolvers = shipped_bindings

    shipped_display = ast_scanner.TaintTracker._cwe338_display_only_draw



    def blind_leaf(leaf_name):
        def mutant(self, node, scope_id=''):
            leaf = (node.func.attr if isinstance(node.func, ast.Attribute)
                    else (node.func.id if isinstance(node.func, ast.Name) else ''))
            if leaf == leaf_name:
                return False
            return shipped_display(self, node, scope_id)
        return mutant

    ast_scanner.TaintTracker._cwe338_display_only_draw = blind_leaf('uniform')
    try:
        loud, _r, _c = scan({'src/transformers/models/m.py': UNIFORM_UNIT}, 'CWE-338')
        results.append(('c338_uniform_proof_blinded', loud == [4]))
    finally:
        ast_scanner.TaintTracker._cwe338_display_only_draw = shipped_display

    ast_scanner.TaintTracker._cwe338_display_only_draw = blind_leaf('sample')
    try:
        loud, _r, _c = scan({'examples/run_qa.py': SAMPLE_INDEX}, 'CWE-338')
        results.append(('c338_sample_proof_blinded', loud == [3]))
    finally:
        ast_scanner.TaintTracker._cwe338_display_only_draw = shipped_display

    shipped_words = ast_scanner.CWE338_SECURITY_NAME_WORDS
    ast_scanner.CWE338_SECURITY_NAME_WORDS = frozenset(shipped_words - {'passwords'})
    try:
        loud, _r, _c = scan({'examples/m.py': C338_FIXTURES['sample_passwords_veto_loud'][1]}, 'CWE-338')
        results.append(('plural_veto_completion_is_load_bearing', loud == []))
    finally:
        ast_scanner.CWE338_SECURITY_NAME_WORDS = shipped_words

    shipped_secrets = ast_scanner.TaintTracker._compares_two_secrets
    shipped_assertion = ast_scanner.TaintTracker._c208_is_unit_test_assertion

    def without_constant_refusal(self, node, file_path=''):
        operands = [node.left] + list(node.comparators)
        if any(isinstance(o, ast.Constant) for o in operands):
            return not self._c208_is_tensor_dimension_compare(node, file_path)
        return shipped_secrets(self, node, file_path)

    ast_scanner.TaintTracker._compares_two_secrets = without_constant_refusal
    try:
        loud, _r, _c = scan({'tests/test_m.py': C208_FIXTURES['test_credential_int_quiet'][1]}, 'CWE-208')
        loud_plain, _rp, _cp = scan({'tests/test_m.py': C208_FIXTURES['test_plain_int_quiet'][1]}, 'CWE-208')
        results.append(('c208_constant_refusal_is_load_bearing', loud == [2] and loud_plain == []))
    finally:
        ast_scanner.TaintTracker._compares_two_secrets = shipped_secrets

    ast_scanner.TaintTracker._compares_two_secrets = without_constant_refusal
    ast_scanner.TaintTracker._c208_is_unit_test_assertion = lambda self, node, file_path='': False
    try:
        loud, _r, _c = scan({'tests/test_m.py': C208_FIXTURES['test_credential_int_quiet'][1]}, 'CWE-208')
        loud_plain, _rp, _cp = scan({'tests/test_m.py': C208_FIXTURES['test_plain_int_quiet'][1]}, 'CWE-208')
        results.append(('c208_both_guards_blinded_moves_the_tier', loud == [2] and loud_plain == []))
    finally:
        ast_scanner.TaintTracker._compares_two_secrets = shipped_secrets
        ast_scanner.TaintTracker._c208_is_unit_test_assertion = shipped_assertion

    shipped_exempt = ast_scanner.TaintTracker._sink_context_exempt

    def with_numeric_spec_exemption(self, cwe_id, node, scope_id):
        if cwe_id == 'CWE-117' and node.args and isinstance(node.args[0], ast.JoinedStr):
            fields = [v for v in node.args[0].values if isinstance(v, ast.FormattedValue)]
            if fields and all(
                    getattr(v.format_spec, 'values', None)
                    and isinstance(v.format_spec.values[0], ast.Constant)
                    and ',' in str(v.format_spec.values[0].value) for v in fields):
                return True
        return shipped_exempt(self, cwe_id, node, scope_id)

    ast_scanner.TaintTracker._sink_context_exempt = with_numeric_spec_exemption
    try:
        loud_mut, _r, _c = trainer_rows()
        silenced = [line for line in BLESSED_C117_TRAINER if line not in loud_mut]
        # The mutant has to remove exactly the blessed block and nothing else: on this corpus the
        # predicate's yield is 8 rows, all 8 are true positives, so 0 FPs is the whole story.
        results.append(('c117_numeric_spec_refusal_is_load_bearing',
                        len(silenced) == len(BLESSED_C117_TRAINER)
                        and bool(SHIPPED_TRAINER_LOUD)
                        and len(SHIPPED_TRAINER_LOUD) - len(loud_mut) == len(silenced)))
    finally:
        ast_scanner.TaintTracker._sink_context_exempt = shipped_exempt

    shipped_facts = ast_scanner.TaintTracker._c22_operator_facts
    shipped_facts_on = ast_scanner.TaintTracker._c22_operator_facts_on
    shipped_facts_build = ast_scanner.TaintTracker._c22_operator_facts_build
    shipped_open_pred = ast_scanner.TaintTracker._c22_is_operator_program_open
    shipped_expr_pred = ast_scanner.TaintTracker._c22_path_is_operator_supplied
    shipped_path_names = ast_scanner.TaintTracker._c22_module_path_names
    shipped_c770_read = ast_scanner.TaintTracker._c770_read_comes_from_operator_program
    shipped_ns_root = ast_scanner.TaintTracker._c22_is_namespace_root
    shipped_scope_binds = ast_scanner.TaintTracker._c22_scope_binds

    # M1: the `__main__` guard conjunct is the fact that separates a program from a library. The
    # mutant forces it at the tree-level fact source and keeps the names the file really parsed, so
    # it tests the conjunct and not the token screen that reads the same two facts.
    ast_scanner.TaintTracker._c22_operator_facts_on = lambda self, tree: (
        True, shipped_facts_build(self, tree)[1])
    try:
        loud, _r, _c = scan({'src/m.py': C22_OPERATOR_FIXTURES['no_main_guard_stays_loud'][1]},
                            'CWE-22')
        results.append(('c22_main_guard_conjunct_is_load_bearing', loud == []))
    finally:
        ast_scanner.TaintTracker._c22_operator_facts_on = shipped_facts_on

    # M2: presence facts with the value chain dropped -- the Rung-1 form the doctrine forbids. Every
    # fixture below is an absence or an unresolvable value, and only the two environ-rooted rows,
    # whose own argument the chain does resolve, survive the mutant.
    def presence_only(self, node, mod_name):
        if not isinstance(node, ast.Call):
            return False
        if (ast_scanner.dotted_name(node.func) or '') not in ast_scanner.FILE_OPEN_FUNCS:
            return False
        guarded, names = shipped_facts(self, mod_name)
        return bool(guarded and names)

    def presence_only_expr(self, expr, mod_name):
        guarded, names = shipped_facts(self, mod_name)
        return bool(guarded and names and expr is not None)

    ast_scanner.TaintTracker._c22_is_operator_program_open = presence_only
    ast_scanner.TaintTracker._c22_path_is_operator_supplied = presence_only_expr
    try:
        quiet_rows = []
        for name in ('uncalled_function_stays_loud', 'unknown_call_stays_loud',
                     'unknown_wrap_stays_loud', 'splat_call_stays_loud'):
            loud, _r, _c = scan({'src/m.py': C22_OPERATOR_FIXTURES[name][1]}, 'CWE-22')
            quiet_rows.append(loud == [])
        env_loud, _re, _ce = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['environ_value_stays_loud'][1]}, 'CWE-22')
        env_rm_loud, _rm, _cm = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['environ_rmtree_stays_loud'][1]}, 'CWE-22')
        results.append(('c22_value_chain_is_load_bearing',
                        all(quiet_rows) and env_loud == [14] and env_rm_loud == [9]))
    finally:
        ast_scanner.TaintTracker._c22_is_operator_program_open = shipped_open_pred
        ast_scanner.TaintTracker._c22_path_is_operator_supplied = shipped_expr_pred

    # M3: a bare wrapper name proves nothing until the import binding is there.
    ast_scanner.TaintTracker._c22_module_path_names = lambda self, tree: frozenset({'removeprefix'})
    try:
        loud, _r, _c = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['unbound_wrapper_stays_loud'][1]}, 'CWE-22')
        results.append(('c22_wrapper_binding_is_load_bearing', loud == []))
    finally:
        ast_scanner.TaintTracker._c22_module_path_names = shipped_path_names

    # M4: the CWE-770 unbounded read only stays quiet because the open underneath it was proven.
    ast_scanner.TaintTracker._c770_read_comes_from_operator_program = (
        lambda self, node, mod_name: False)
    try:
        loud, _r, _c = scan({C770_OPERATOR_READ[0]: C770_OPERATOR_READ[1]}, 'CWE-770')
        results.append(('c770_operator_program_read_is_load_bearing', loud == [11]))
    finally:
        ast_scanner.TaintTracker._c770_read_comes_from_operator_program = shipped_c770_read

    # M5: tier 9 has to be about this predicate, not about a line that no exemption could reach.
    ast_scanner.TaintTracker._c22_is_operator_program_open = lambda self, node, mod_name: True
    ast_scanner.TaintTracker._c22_path_is_operator_supplied = lambda self, expr, mod_name: True
    try:
        with open(os.path.join(BIG8_CORPUS, REACH_MUTATION_LEAF),
                  encoding='utf-8', errors='replace') as handle:
            common_src = handle.read()
        loud, _r, _c = scan({REACH_MUTATION_KEY: common_src}, 'CWE-22')
        results.append(('c22_operator_reach_tier_moves_when_forced',
                        REACH_MUTATION_LINE not in loud))
    finally:
        ast_scanner.TaintTracker._c22_is_operator_program_open = shipped_open_pred
        ast_scanner.TaintTracker._c22_path_is_operator_supplied = shipped_expr_pred

    # M6: the holder trust is a proof about the binding, not about the spelling of the name. Reduced
    # to "this name is fed a parse_args() somewhere" it silences every borrowed-authority fixture at
    # once -- exactly the false negative the scope tables exist to prevent.
    ast_scanner.TaintTracker._c22_is_namespace_root = (
        lambda self, tree, node, name, argparse_names, path=None, seen=None: name in argparse_names)
    try:
        borrowed = []
        for fixture in ('holder_is_param_stays_loud', 'holder_field_written_stays_loud',
                        'loop_target_shadows_stays_loud', 'lambda_param_shadows_stays_loud',
                        'nested_tuple_rebind_stays_loud'):
            loud, _r, _c = scan({'src/m.py': C22_OPERATOR_FIXTURES[fixture][1]}, 'CWE-22')
            borrowed.append(loud == [])
        rebound, _r2, _c2 = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['holder_rebound_stays_loud'][1]}, 'CWE-22')
        results.append(('c22_namespace_binding_proof_is_load_bearing',
                        all(borrowed) and rebound == [15]))
    finally:
        ast_scanner.TaintTracker._c22_is_namespace_root = shipped_ns_root

    # M7: mixing scopes lets one function's `args = chkpt["cfg"]` poison a different function's
    # command line. The merged table has to move the converter-shaped fixture and nothing else.
    def merged_scopes(self, tree):
        binds, mutated = shipped_scope_binds(self, tree)
        flat = {}
        for (_owner, bound), values in binds.items():
            flat.setdefault(('', bound), []).extend(values)
        return flat, mutated

    ast_scanner.TaintTracker._c22_scope_binds = merged_scopes
    try:
        peek_loud, _r, _c = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['other_scope_local_quiet'][1]}, 'CWE-22')
        handoff, _r2, _c2 = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['namespace_handoff_quiet'][1]}, 'CWE-22')
        positional, _r3, _c3 = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['operator_positional_call'][1]}, 'CWE-22')
        results.append(('c22_scope_separation_is_load_bearing',
                        peek_loud == [9] and handoff == [] and positional == []))
    finally:
        ast_scanner.TaintTracker._c22_scope_binds = shipped_scope_binds

    # M8: the write veto is per field, so blinding it must quiet the written field and leave the
    # never-written reads alone.
    ast_scanner.TaintTracker._c22_scope_binds = (
        lambda self, tree: (shipped_scope_binds(self, tree)[0], frozenset()))
    try:
        written, _r, _c = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['holder_field_written_stays_loud'][1]}, 'CWE-22')
        nested, _r2, _c2 = scan(
            {'src/m.py': C22_OPERATOR_FIXTURES['nested_tuple_rebind_stays_loud'][1]}, 'CWE-22')
        results.append(('c22_field_mutation_veto_is_load_bearing',
                        written == [] and nested == [9]))
    finally:
        ast_scanner.TaintTracker._c22_scope_binds = shipped_scope_binds

    # M9: slice F's arm is what quiets the operator-program log lines. Remove the arm and every one
    # of the four quiet fixtures registers its second sink again.
    shipped_c117_arm = ast_scanner.TaintTracker._cwe117_message_is_operator_sealed
    ast_scanner.TaintTracker._cwe117_message_is_operator_sealed = (
        lambda self, node, tree, shadowed: False)
    try:
        moved = []
        for fixture in ('argv_field_quiet', 'numeric_local_quiet',
                        'json_config_from_argv_quiet'):
            loud, _r, records = scan(
                {'src/m.py': C117_OPERATOR_FIXTURES[fixture][1]}, 'CWE-117')
            moved.append(records == 2 and len(loud) == 2)
        held = []
        for fixture in ('client_text_stays_loud', 'mixed_client_and_argv_stays_loud',
                        'rebound_client_stays_loud', 'json_config_from_unknown_stays_loud'):
            loud, _r, records = scan(
                {'src/m.py': C117_OPERATOR_FIXTURES[fixture][1]}, 'CWE-117')
            held.append(records == 2 and len(loud) == 2)
        results.append(('c117_operator_program_arm_is_load_bearing',
                        all(moved) and all(held)))
    finally:
        ast_scanner.TaintTracker._cwe117_message_is_operator_sealed = shipped_c117_arm

    # M10: the newline-free proof is a separate arm from the argv proof. Blinding it must quiet
    # nothing and re-loud exactly the two numeric fixtures, while the argv fixture stays quiet.
    shipped_newline_free = ast_scanner.TaintTracker._c22_value_is_newline_free
    ast_scanner.TaintTracker._c22_value_is_newline_free = (
        lambda self, tree, expr, shadowed, depth=0, seen=None: False)
    try:
        numeric, _r, _c = scan(
            {'src/m.py': C117_OPERATOR_FIXTURES['numeric_local_quiet'][1]}, 'CWE-117')
        argv, _r3, _c3 = scan(
            {'src/m.py': C117_OPERATOR_FIXTURES['argv_field_quiet'][1]}, 'CWE-117')
        results.append(('c117_newline_free_proof_is_load_bearing',
                        len(numeric) == 2 and argv == [12]))
    finally:
        ast_scanner.TaintTracker._c22_value_is_newline_free = shipped_newline_free

    # M10b: the same proof asserted the other way. If every value were newline-free, the literal
    # carrying a real line break and the shadowed `len` would both clear, and the two fixtures that
    # depend on refusing them would go quiet.
    ast_scanner.TaintTracker._c22_value_is_newline_free = (
        lambda self, tree, expr, shadowed, depth=0, seen=None: True)
    try:
        flipped = [newline_free_proof(source, hole) for _n, source, hole, _e in C117_VALUE_PROOFS]
        moved = [got is True and expected is False
                 for (_n, _s, _h, expected), got in zip(C117_VALUE_PROOFS, flipped)]
        results.append(('c117_value_proof_refusals_are_load_bearing',
                        any(moved) and all(flipped)))
    finally:
        ast_scanner.TaintTracker._c22_value_is_newline_free = shipped_newline_free

    # M11: a config namespace parsed from a file is trusted only as far as the file argument is.
    # Admitting `parse_json_file` as a root on sight quiets the fixture whose file came from an
    # unknown call -- the exact false negative the recursive proof exists to stop.
    shipped_program_calls = ast_scanner.CWE22_OPERATOR_PROGRAM_CALLS
    ast_scanner.CWE22_OPERATOR_PROGRAM_CALLS = ast_scanner.CWE22_OPERATOR_ROOT_CALLS
    try:
        unknown, _r, records = scan(
            {'src/m.py': C117_OPERATOR_FIXTURES['json_config_from_unknown_stays_loud'][1]},
            'CWE-117')
        results.append(('c117_json_file_argument_proof_is_load_bearing',
                        records == 1 or len(unknown) < 2))
    finally:
        ast_scanner.CWE22_OPERATOR_PROGRAM_CALLS = shipped_program_calls

    # M12: the rule is every logged value, not any. Feeding the proof only the first value quiets a
    # line that still interpolates a client payload.
    shipped_logged_values = ast_scanner.TaintTracker._cwe117_logged_values
    ast_scanner.TaintTracker._cwe117_logged_values = (
        lambda self, node: shipped_logged_values(self, node)[:1])
    try:
        mixed, _r, records = scan(
            {'src/m.py': C117_OPERATOR_FIXTURES['mixed_client_and_argv_stays_loud'][1]},
            'CWE-117')
        results.append(('c117_every_value_rule_is_load_bearing', records == 1 or len(mixed) < 2))
    finally:
        ast_scanner.TaintTracker._cwe117_logged_values = shipped_logged_values

    # M13/M14: the two value caches move no finding row on their own -- they are pure caching -- so
    # each key half has to be shown load-bearing separately. Dropping the expression from the scope
    # key hands `small()`'s arithmetic binding to `big()`, which reads the request, and line 22 of the
    # split fixture goes quiet (measured [12] against the shipped [12, 22]). Dropping the name hands
    # the namespace's own binding to the `args.model_dir` question asked about the same node.
    shipped_bound = ast_scanner.TaintTracker._c22_bound_values
    shipped_bound_on = ast_scanner.TaintTracker._c22_bound_values_on

    def bound_by_name_only(self, tree, node, name):
        cache = tree.__dict__.get('_c22_bound_values')
        if cache is None:
            cache = tree.__dict__['_c22_bound_values'] = {}
        key = ('', name)
        if key not in cache:
            cache[key] = shipped_bound_on(self, tree, node, name)
        return cache[key]

    def bound_by_node_only(self, tree, node, name):
        cache = tree.__dict__.get('_c22_bound_values')
        if cache is None:
            cache = tree.__dict__['_c22_bound_values'] = {}
        key = (id(node),)
        if key not in cache:
            cache[key] = shipped_bound_on(self, tree, node, name)
        return cache[key]

    split_source = C117_OPERATOR_FIXTURES['same_name_two_scopes_split'][1]
    argv_source = C117_OPERATOR_FIXTURES['argv_field_quiet'][1]
    clean_split = scan({'src/m.py': split_source}, 'CWE-117')[0]
    clean_argv = scan({'src/m.py': argv_source}, 'CWE-117')[0]
    ast_scanner.TaintTracker._c22_bound_values = bound_by_name_only
    try:
        name_only = scan({'src/m.py': split_source}, 'CWE-117')[0]
    finally:
        ast_scanner.TaintTracker._c22_bound_values = shipped_bound
    results.append(('c22_bound_value_cache_scope_key_is_load_bearing',
                    clean_split == [12, 22] and name_only == [12]))

    spellings = ['args', 'args.model_dir']
    split_answers = bound_value_probe(argv_source, 'args.model_dir', spellings)
    ast_scanner.TaintTracker._c22_bound_values = bound_by_node_only
    try:
        collapsed = bound_value_probe(argv_source, 'args.model_dir', spellings)
    finally:
        ast_scanner.TaintTracker._c22_bound_values = shipped_bound
    results.append(('c22_bound_value_cache_name_key_is_load_bearing',
                    len(split_answers) == 2 and split_answers[0] != split_answers[1]
                    and collapsed[0] == collapsed[1]))

    # M15: the arm caches its own verdict per log statement. A cache that answers every later
    # statement with the first verdict would quiet the request line behind the arithmetic line.
    def sticky_arm(self, node, tree, shadowed):
        store = getattr(sticky_arm, 'store', None)
        if store is None:
            store = sticky_arm.store = {}
        if store:
            return store['verdict']
        verdict = shipped_c117_arm(self, node, tree, shadowed)
        store['verdict'] = verdict
        return verdict

    sticky_arm.store = {}
    ast_scanner.TaintTracker._cwe117_message_is_operator_sealed = sticky_arm
    try:
        sticky = scan({'src/m.py': split_source}, 'CWE-117')[0]
    finally:
        ast_scanner.TaintTracker._cwe117_message_is_operator_sealed = shipped_c117_arm
    results.append(('c117_verdict_cache_key_is_load_bearing', sticky != clean_split))

    # M16: the facts screen may only ever decline a module that provably holds neither fact. Tightening
    # the tokens to one root spelling hides the namespaces of every file that spells it differently,
    # so both fixture sets must come back loud; switching the screen off entirely must change nothing,
    # which is the exact statement that it is a fast path and not a filter.
    shipped_tokens = ast_scanner.CWE22_OPERATOR_FACT_TOKENS
    ast_scanner.CWE22_OPERATOR_FACT_TOKENS = ('__name__', 'parse_args_into_dataclasses')
    try:
        strict_argv = scan({'src/m.py': argv_source}, 'CWE-117')[0]
        strict_split = scan({'src/m.py': split_source}, 'CWE-117')[0]
    finally:
        ast_scanner.CWE22_OPERATOR_FACT_TOKENS = shipped_tokens
    ast_scanner.CWE22_OPERATOR_FACT_TOKENS = ()
    try:
        unshielded_argv = scan({'src/m.py': argv_source}, 'CWE-117')[0]
        unshielded_split = scan({'src/m.py': split_source}, 'CWE-117')[0]
    finally:
        ast_scanner.CWE22_OPERATOR_FACT_TOKENS = shipped_tokens
    results.append(('c22_operator_fact_screen_is_superset_only',
                    strict_argv != clean_argv and strict_split != clean_split
                    and unshielded_argv == clean_argv and unshielded_split == clean_split))

    restored = (ast_scanner.TaintTracker._c22_is_literal_readonly_open is shipped_literal
                and ast_scanner.TaintTracker._c22_is_hub_cache_read is shipped_resolver
                and ast_scanner.TaintTracker._c22_module_hub_resolvers is shipped_bindings
                and ast_scanner.TaintTracker._cwe338_display_only_draw is shipped_display
                and ast_scanner.CWE338_SECURITY_NAME_WORDS is shipped_words
                and ast_scanner.TaintTracker._compares_two_secrets is shipped_secrets
                and ast_scanner.TaintTracker._sink_context_exempt is shipped_exempt
                and ast_scanner.TaintTracker._c22_operator_facts is shipped_facts
                and ast_scanner.TaintTracker._c22_operator_facts_on is shipped_facts_on
                and ast_scanner.TaintTracker._c22_operator_facts_build is shipped_facts_build
                and ast_scanner.CWE22_OPERATOR_FACT_TOKENS == ('__name__', 'parse_')
                and ast_scanner.TaintTracker._c22_is_operator_program_open is shipped_open_pred
                and ast_scanner.TaintTracker._c22_path_is_operator_supplied is shipped_expr_pred
                and ast_scanner.TaintTracker._c22_module_path_names is shipped_path_names
                and ast_scanner.TaintTracker._c22_is_namespace_root is shipped_ns_root
                and ast_scanner.TaintTracker._c22_scope_binds is shipped_scope_binds
                and ast_scanner.TaintTracker._c770_read_comes_from_operator_program is shipped_c770_read
                and ast_scanner.TaintTracker._c208_is_unit_test_assertion is shipped_assertion
                and ast_scanner.TaintTracker._cwe117_message_is_operator_sealed is shipped_c117_arm
                and ast_scanner.TaintTracker._c22_value_is_newline_free is shipped_newline_free
                and ast_scanner.TaintTracker._cwe117_logged_values is shipped_logged_values
                and ast_scanner.TaintTracker._c22_bound_values is shipped_bound
                and ast_scanner.TaintTracker._c22_bound_values_on is shipped_bound_on
                and ast_scanner.CWE22_OPERATOR_PROGRAM_CALLS is shipped_program_calls)
    results.append(('engine_restored_after_mutation', restored))
    for name, ok in results:
        print(f'  {"ok " if ok else "FAIL"} mutation {name} -> '
              f'{"moves the tier" if ok else "does not move"}')
    return [name for name, ok in results if not ok]


def main() -> int:
    failures = []
    for check in (check_baseline_domain, check_slice_a, check_slice_b, check_slice_c,
                   check_slice_d, check_slice_e, check_slice_f, check_operator_reach,
                   check_blessed_lines_stay_loud, check_source_shape,
                   check_refused_value_slice):
        failures.extend(check())
    failures.extend(run_mutations())
    if failures:
        print('VERDICT: FAIL - ' + '; '.join(str(f) for f in failures))
        return 1
    print('VERDICT: PASS - the literal read-only open, the hub cache-resolver read and the '
          'operator-program open/delete never register, all 24 blessed CWE-22 keys stay loud with '
          'the corpus-name shield removed, the two CWE-338 value domains are quiet while every '
          'credential veto and all 8 blessed lines stay loud, the CWE-208 constant partition holds '
          'under two independent guards, the refused CWE-117 numeric-spec slice keeps all 8 trainer '
          'keys loud, the CWE-117 operator-program arm quiets only argv and newline-free log values, '
          'and every conjunct moves under its own mutation.')
    return 0


if __name__ == '__main__':
    sys.exit(main())