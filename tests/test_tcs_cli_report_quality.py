from __future__ import annotations


FILES = {
    "secret_app.py": (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        'SECRET_KEY = "super-secret-value-abcdef123456"\n'
        'app.run(host="0.0.0.0", debug=True)\n'
    ),
    "csrf_app.py": (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        '@app.route("/unsafe", methods=["POST"])\n'
        "def unsafe():\n"
        '    return "unsafe"\n'
    ),
    "sqli_app.py": (
        "from flask import request\n"
        "import sqlite3\n"
        'uid = request.args.get("id")\n'
        'cursor = sqlite3.connect("app.db").cursor()\n'
        'cursor.execute("select * from users where id = " + uid)\n'
    ),
    "cmdi_app.py": (
        "from flask import request\n"
        "import subprocess\n"
        'name = request.args.get("name")\n'
        'subprocess.run("ls " + name, shell=True)\n'
    ),
    "ssrf_app.py": (
        "from flask import request\n"
        "import urllib.request\n"
        'url = request.args.get("url")\n'
        "urllib.request.urlopen(url)\n"
    ),
}


def _active(result):
    return [finding for finding in result["findings"] if not finding.get("suppressed")]


def _one(findings, file_name, cwe, line_number=None):
    matches = [
        finding for finding in findings
        if finding["file"] == file_name and finding["cwe"] == cwe
        and (line_number is None or finding["line_number"] == line_number)
    ]
    assert len(matches) == 1, (file_name, cwe, matches)
    return matches[0]


def test_static_reports_do_not_fabricate_taint_or_confidence():
    from tcs_cli import execute_tcs_scan

    result = execute_tcs_scan(dict(FILES), secrets=True)
    findings = _active(result)

    sites = [(f["file"], f["line_number"], f["cwe"]) for f in findings]
    assert len(sites) == len(set(sites)), sites

    for file_name, cwe in (
        ("secret_app.py", "CWE-798"),
        ("secret_app.py", "CWE-668"),
        ("secret_app.py", "CWE-489"),
        ("csrf_app.py", "CWE-352"),
    ):
        finding = _one(findings, file_name, cwe)
        assert finding["confidence_label"] == "STATIC (PATTERN_MATCH)"
        trace_text = " ".join(finding["flow_trace"]).lower()
        assert "user_input" not in trace_text
        assert "handler)" not in trace_text

    secret = _one(findings, "secret_app.py", "CWE-798")
    assert secret.get("is_secret") is True
    assert secret["source_line"] == 3
    assert any(item["file"] == "secret_app.py" for item in result["secret_findings"])
    assert len([f for f in findings if f["cwe"] == "CWE-798"]) == 1


def test_real_dataflow_reports_keep_source_and_sink_trace():
    from tcs_cli import execute_tcs_scan

    findings = _active(execute_tcs_scan(dict(FILES), secrets=True))

    for file_name, cwe, sink_name, line_number in (
        ("sqli_app.py", "CWE-89", "cursor.execute", 5),
        ("cmdi_app.py", "CWE-78", "subprocess.run", 4),
        ("ssrf_app.py", "CWE-918", "urllib.request.urlopen", 4),
    ):
        finding = _one(findings, file_name, cwe, line_number)
        assert finding["confidence_label"] == "CONFIRMED"
        assert finding["flow_trace"][0].startswith("Source: request.args.get")
        assert finding["flow_trace"][-1] == (
            f"Sink: {sink_name} ({file_name}:{finding['line_number']})"
        )


def test_unknown_confidence_falls_back_to_static_pattern():
    from tcs_cli import format_confidence

    assert format_confidence([], None) == "STATIC (PATTERN_MATCH)"
