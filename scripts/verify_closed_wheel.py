import pathlib, sys, zipfile
FEXT = (".c", ".h", ".cpp", ".pyx", ".pxd", ".db", ".sqlite", ".sqlite3", ".env", ".pem", ".key")
FNAME = ("tcs_users", "cwe_blueprint", ".qoder", "agents.md")
RBIN = ("ast_scanner", "cli", "rule_engine", "secret_scanner", "master_rules_bank", "_tcs_sink_names", "tcs_config", "banner", "scanners/sca_scanner")
STUB = ("from . import _pkg_init as _m" + chr(10) + "globals().update({k: v for k, v in vars(_m).items() if not k.startswith(" + chr(39) + "__" + chr(39) + ")})").strip()
def check_wheel(whl):
    fails = []
    with zipfile.ZipFile(whl, "r") as zf:
        names = zf.namelist()
        bins = [n for n in names if n.endswith((".so", ".pyd"))]
        pys = [n for n in names if n.endswith(".py")]
        for n in names:
            low = n.lower()
            if low.endswith(FEXT): fails.append("FORBIDDEN_EXT:" + n)
            if any(b in low for b in FNAME): fails.append("FORBIDDEN_NAME:" + n)
        for pyf in pys:
            raw = zf.read(pyf).decode("utf-8", errors="replace").strip()
            if not (pyf.endswith("/__init__.py") and raw in ("", STUB)): fails.append("SOURCE_LEAK_PY:" + pyf)
        for req in RBIN:
            if not any(b.startswith(req + ".") for b in bins): fails.append("MISSING_BINARY:" + req)
        if "data/rules_catalog.json" not in names: fails.append("MISSING_DATA:data/rules_catalog.json")
        mf = [n for n in names if n.endswith(".dist-info/METADATA")]
        if not mf: fails.append("MISSING_METADATA")
        else:
            mt = zf.read(mf[0]).decode("utf-8", errors="replace")
            if "Name: timecs" not in mt or "Proprietary" not in mt: fails.append("BAD_METADATA")
            for ln in mt.splitlines():
                if ln.startswith(("License:", "License-Expression:")) and "MIT" in ln: fails.append("LICENSE_LEAK:" + ln)
        ep = [n for n in names if n.endswith(".dist-info/entry_points.txt")]
        if not ep or "timecs = cli:main" not in zf.read(ep[0]).decode("utf-8", errors="replace"): fails.append("MISSING_ENTRYPOINT")
        print("[verify]", whl.name, "binaries=", len(bins), "stubs=", len(pys))
    return fails
def main():
    dd = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "dist").resolve()
    sd = list(dd.glob("*.tar.gz")) + list(dd.glob("*.zip"))
    if sd: print("FAIL: source archive forbidden:", [p.name for p in sd]); return 1
    whls = sorted(dd.glob("*.whl"))
    if not whls: print("FAIL: no .whl found"); return 1
    fails = [f for w in whls for f in check_wheel(w)]
    if fails:
        for f in fails: print("FAIL:", f)
        return 1
    print("VERDICT: PASS -", len(whls), "closed wheel(s) verified, 0 leaks.")
    return 0
if __name__ == "__main__": raise SystemExit(main())
