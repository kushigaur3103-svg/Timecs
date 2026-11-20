import argparse, ast, os, pathlib, shutil, subprocess, sys, tempfile, tomllib
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
STUB = "from . import _pkg_init as _m" + chr(10) + "globals().update({k: v for k, v in vars(_m).items() if not k.startswith(" + chr(39) + "__" + chr(39) + ")})" + chr(10)
def _has_code(p):
    for n in ast.parse(p.read_text(encoding="utf-8")).body:
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str): continue
        return True
    return False
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="dist")
    out_dir = (REPO_ROOT / ap.parse_args().out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    for f in list(out_dir.glob("*.whl")) + list(out_dir.glob("*.tar.gz")): f.unlink()
    meta = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    py_modules = list(meta["tool"]["setuptools"]["py-modules"])
    packages = list(meta["tool"]["setuptools"]["packages"])
    sys.path.insert(0, str(REPO_ROOT))
    import rule_engine
    sinks = sorted(rule_engine.SINK_MATCHER_NAMES)
    assert len(sinks) >= 50, "SINK_MATCHER_NAMES too small"
    cat = REPO_ROOT / "data" / "rules_catalog.json"
    assert cat.is_file(), "Missing data/rules_catalog.json"
    with tempfile.TemporaryDirectory(prefix="tcs_closed_build_") as tmp:
        st = pathlib.Path(tmp)
        shutil.copy2(REPO_ROOT / "INSTRUCTIONS_OF_TIMECS.md", st / "INSTRUCTIONS_OF_TIMECS.md")
        (st / "_tcs_data").mkdir(parents=True, exist_ok=True)
        shutil.copy2(cat, st / "_tcs_data" / "rules_catalog.json")
        targets, stubs = [], []
        for m in py_modules:
            src = REPO_ROOT / (m + ".py")
            shutil.copy2(src, st / src.name)
            targets.append((m, src.name))
        (st / "_tcs_sink_names.py").write_text("SINK_MATCHER_NAMES = frozenset(" + repr(sinks) + ")" + chr(10), encoding="utf-8", newline=chr(10))
        targets.append(("_tcs_sink_names", "_tcs_sink_names.py"))
        for pkg in packages:
            pr = pathlib.Path(*pkg.split("."))
            (st / pr).mkdir(parents=True, exist_ok=True)
            for pyf in sorted((REPO_ROOT / pr).glob("*.py")):
                if pyf.name == "__init__.py":
                    if _has_code(pyf):
                        ir = (pr / "_pkg_init.py").as_posix()
                        shutil.copy2(pyf, st / ir)
                        targets.append((pkg + "._pkg_init", ir))
                        (st / pr / "__init__.py").write_text(STUB, encoding="utf-8", newline=chr(10))
                    else:
                        (st / pr / "__init__.py").write_text("", encoding="utf-8", newline=chr(10))
                    stubs.append((pr / "__init__.py").as_posix())
                else:
                    rel = (pr / pyf.name).as_posix()
                    shutil.copy2(pyf, st / rel)
                    targets.append((pkg + "." + pyf.stem, rel))
        pt = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8").replace("requires = ["+chr(34)+"setuptools>=77"+chr(34)+"]", "requires = ["+chr(34)+"setuptools>=77"+chr(34)+", "+chr(34)+"Cython>=3.0"+chr(34)+"]", 1)
        (st / "pyproject.toml").write_text(pt, encoding="utf-8", newline=chr(10))
        sl = [
            "import os, pathlib, shutil",
            "from setuptools import Extension, setup",
            "from setuptools.command.build_py import build_py",
            "from Cython.Build import cythonize",
            "TARGETS = " + repr(targets),
            "INIT_STUBS = " + repr(stubs),
            "class ClosedBuildPy(build_py):",
            "    def run(self):",
            "        os.makedirs(self.build_lib, exist_ok=True)",
            "        for stub in INIT_STUBS:",
            "            dst = pathlib.Path(self.build_lib) / stub",
            "            dst.parent.mkdir(parents=True, exist_ok=True)",
            "            shutil.copy2(stub, dst)",
            "        dd = pathlib.Path(self.build_lib) / "+chr(39)+"data"+chr(39)+" / "+chr(39)+"rules_catalog.json"+chr(39),
            "        dd.parent.mkdir(parents=True, exist_ok=True)",
            "        shutil.copy2("+chr(39)+"_tcs_data/rules_catalog.json"+chr(39)+", dd)",
            "ea = ["+chr(39)+"/O1"+chr(39)+"] if os.name == "+chr(39)+"nt"+chr(39)+" else ["+chr(39)+"-O1"+chr(39)+"]",
            "exts = [Extension(n, [s], extra_compile_args=ea) for n, s in TARGETS]",
            "setup(cmdclass={"+chr(39)+"build_py"+chr(39)+": ClosedBuildPy}, ext_modules=cythonize(exts, compiler_directives={"+chr(39)+"language_level"+chr(39)+": "+chr(39)+"3"+chr(39)+", "+chr(39)+"binding"+chr(39)+": True, "+chr(39)+"always_allow_keywords"+chr(39)+": True}, nthreads=1, quiet=False))",
        ]
        (st / "setup.py").write_text(chr(10).join(sl) + chr(10), encoding="utf-8", newline=chr(10))
        print("[build] compiling", len(targets), "Cython modules...")
        subprocess.run([sys.executable, "-m", "pip", "wheel", "-v", "--no-deps", "--no-build-isolation", "--wheel-dir", str(out_dir), str(st)], check=True)
    print("[build] done:", [w.name for w in sorted(out_dir.glob("*.whl"))])
    return 0
if __name__ == "__main__": raise SystemExit(main())
