"""CI/CD and Infrastructure-as-Code security scanner -- stdlib only.

Four rules over three artefact families. The existing CWE-1357 unpinned-action check lives in
``iac_auditor.audit_workflow`` and is deliberately NOT reimplemented or touched here: this module
adds the injection, permission, privilege and exposure rules beside it.

* CWE-78  ``GHA_SCRIPT_INJECTION`` -- a ``run:`` shell script interpolates an untrusted pull-request,
  issue, comment or review expression. Routing that expression through a step ``env:`` variable and
  quoting ``"$VAR"`` in the script is the safe spelling, and it is safe precisely because the
  expression no longer appears in the script text at all.
* CWE-269 ``GHA_EXCESSIVE_PERMISSIONS_OR_PWN_REQUEST`` -- ``permissions: write-all``, or a
  ``pull_request_target`` workflow that checks out the untrusted PR head.
* CWE-250 ``K8S_PRIVILEGED_CONTAINER`` -- a workload manifest asks for ``privileged``,
  ``allowPrivilegeEscalation``, ``hostNetwork``, ``hostPID`` or ``runAsUser: 0``.
* CWE-732 ``IAC_PUBLIC_EXPOSURE`` -- a Terraform S3 bucket is public-read, or a security group opens
  SSH/RDP to ``0.0.0.0/0``.

Every decision reads a parsed node or a parsed HCL block, never a whole-file pattern sweep, and an
unresolvable value is left alone rather than guessed at.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from . import yaml_lite

__all__ = ["is_iac_security_path", "is_workflow_yaml_path", "is_terraform_path",
           "is_kubernetes_manifest", "audit_iac_security_files"]

WORKFLOW_SUFFIXES = (".yml", ".yaml")
KIND_WORKLOADS = frozenset({"Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"})

# Expressions an outside contributor controls. `github.sha` and `github.ref` on a push are the
# repository's own code and are deliberately absent.
UNTRUSTED_EXPRESSIONS = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.head_ref",
)
PR_HEAD_EXPRESSIONS = (
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
)
_EXPRESSION_RE = re.compile(r"\$\{\{(.+?)\}\}", re.DOTALL)

K8S_TRUE_FLAGS = frozenset({"privileged", "allowPrivilegeEscalation", "hostNetwork", "hostPID"})
PUBLIC_ACLS = frozenset({"public-read", "public-read-write"})
WORLD_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
ADMIN_PORTS = frozenset({22, 3389})

_TF_RESOURCE_RE = re.compile(r'^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
_TF_ATTR_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
_TF_STRING_RE = re.compile(r'"([^"]*)"')


def is_workflow_yaml_path(path: str) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    if not normalized.endswith(WORKFLOW_SUFFIXES):
        return False
    parts = normalized.split("/")
    for index, part in enumerate(parts[:-1]):
        if part == ".github" and index + 1 < len(parts) - 1 and parts[index + 1] == "workflows":
            return True
    return False


def is_terraform_path(path: str) -> bool:
    return str(path).replace("\\", "/").lower().endswith(".tf")


def is_iac_security_path(path: str) -> bool:
    """The path-decidable half of this family: GitHub Actions workflows and Terraform.

    Kubernetes is deliberately not here -- a workload manifest can sit at any path, so it is
    claimed by ``is_kubernetes_manifest`` on content instead of on a directory name.
    """
    return is_workflow_yaml_path(path) or is_terraform_path(path)


def is_kubernetes_manifest(source: str) -> bool:
    # Cheap literal pre-guard: discovery offers every YAML document in a tree to this sniff, and
    # parsing an unrelated config file to learn it is not a manifest is wasted work.
    if "apiVersion" not in source or "kind" not in source:
        return False
    root = yaml_lite.parse(source)
    if not isinstance(root, yaml_lite.Mapping):
        return False
    kind = yaml_lite.get(root, "kind")
    version = yaml_lite.get(root, "apiVersion")
    return (isinstance(kind, yaml_lite.Scalar) and isinstance(version, yaml_lite.Scalar)
            and kind.text.strip() in KIND_WORKLOADS and bool(version.text.strip()))


def _finding(file_path: str, line: int, cwe: str, category: str, severity: str, message: str) -> Dict[str, Any]:
    return {
        "file": file_path,
        "line": max(1, int(line)),
        "cwe": cwe,
        "severity": severity,
        "category": category,
        "message": f"{cwe}: {message}",
    }


def _matching_lines(raw_lines: Sequence[str], node: Any, needle: str) -> Iterator[int]:
    """Exact source lines inside a node's span that contain ``needle``.

    A block scalar's text is joined, so its line offsets are not arithmetic; the span is read back
    against the source instead, which keeps every reported line inside the node it belongs to.
    """
    start = getattr(node, "lineno", 1)
    end = getattr(node, "end_lineno", start)
    for lineno in range(start, min(end, len(raw_lines)) + 1):
        if needle in raw_lines[lineno - 1]:
            yield lineno


# ── GitHub Actions ────────────────────────────────────────────────────────
def _triggers(root: Any) -> Set[str]:
    # `on` is a YAML 1.1 boolean, so PyYAML hands back True; yaml_lite keeps the literal spelling.
    node = yaml_lite.get(root, "on")
    if node is None:
        node = yaml_lite.get(root, "True")
    names: Set[str] = set()
    if isinstance(node, yaml_lite.Scalar):
        names.update(part.strip() for part in node.text.split(",") if part.strip())
    elif isinstance(node, yaml_lite.Sequence):
        for _lineno, item in node.items:
            names.add(yaml_lite.scalar_text(item).strip())
    elif isinstance(node, yaml_lite.Mapping):
        names.update(key for key, _lineno, _value in node.items)
    return names


def _run_nodes(root: Any) -> Iterator[Any]:
    for path, _lineno, node in yaml_lite.walk(root):
        if path and path[-1] == "run" and isinstance(node, yaml_lite.Scalar):
            yield node


def _gha_script_injection(file_path: str, root: Any, raw_lines: Sequence[str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for node in _run_nodes(root):
        reported: Set[int] = set()
        for expression in UNTRUSTED_EXPRESSIONS:
            for lineno in _matching_lines(raw_lines, node, expression):
                if lineno in reported:
                    continue
                line_text = raw_lines[lineno - 1]
                if not _EXPRESSION_RE.search(line_text):
                    continue
                reported.add(lineno)
                findings.append(_finding(
                    file_path, lineno, "CWE-78", "GHA_SCRIPT_INJECTION", "HIGH",
                    f"run: interpolates ${{{{ {expression} }}}} straight into a shell script, so a"
                    " pull-request or issue title can close the quote and execute arbitrary commands"
                    " on the runner. Assign the expression to a step env: variable and reference it"
                    ' as "$VAR" so the shell never parses attacker text'))
    return findings


def _gha_permissions(file_path: str, root: Any, raw_lines: Sequence[str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path, _lineno, node in yaml_lite.walk(root):
        if not path or path[-1] != "permissions" or not isinstance(node, yaml_lite.Scalar):
            continue
        if node.text.strip().lower() != "write-all":
            continue
        scope = "workflow" if len(path) == 1 else f"job {path[1]}"
        findings.append(_finding(
            file_path, node.lineno, "CWE-269", "GHA_EXCESSIVE_PERMISSIONS_OR_PWN_REQUEST", "HIGH",
            f"{scope} grants permissions: write-all, giving the GITHUB_TOKEN write access to every"
            " scope including contents and packages. Grant only the scopes the job actually uses"))
    if "pull_request_target" not in _triggers(root):
        return findings
    for _path, _lineno, node in yaml_lite.walk(root):
        if not isinstance(node, yaml_lite.Scalar):
            continue
        for expression in PR_HEAD_EXPRESSIONS:
            for lineno in _matching_lines(raw_lines, node, expression):
                findings.append(_finding(
                    file_path, lineno, "CWE-269", "GHA_EXCESSIVE_PERMISSIONS_OR_PWN_REQUEST", "CRITICAL",
                    f"pull_request_target runs with the base repository's token and secrets, and this"
                    f" line checks out {expression} -- the contributor's untrusted code. That"
                    " combination executes attacker code with write permissions. Use"
                    " pull_request, or drop the checkout of the PR head"))
    return findings


# ── Kubernetes ────────────────────────────────────────────────────────────
def _kubernetes_privileges(file_path: str, root: Any) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    kind = yaml_lite.scalar_text(yaml_lite.get(root, "kind")).strip()
    for path, _lineno, node in yaml_lite.walk(root):
        if not path or not isinstance(node, yaml_lite.Scalar):
            continue
        key = path[-1]
        value = node.text.strip().strip("'\"").lower()
        if key in K8S_TRUE_FLAGS and value == "true":
            findings.append(_finding(
                file_path, node.lineno, "CWE-250", "K8S_PRIVILEGED_CONTAINER", "HIGH",
                f"{kind} sets {key}: true, which removes the container's isolation from the host."
                f" Set {key}: false and grant only the specific capability the workload needs"))
        elif key == "runAsUser" and value == "0":
            findings.append(_finding(
                file_path, node.lineno, "CWE-250", "K8S_PRIVILEGED_CONTAINER", "HIGH",
                f"{kind} sets runAsUser: 0, so the workload runs as root inside the container."
                " Set runAsNonRoot: true and a non-zero runAsUser"))
    return findings


# ── Terraform (HCL) ───────────────────────────────────────────────────────
def _hcl_blocks(source: str) -> List[Tuple[str, int, int, int]]:
    """[(header, header_lineno, body_first_line, body_last_line)] for every brace block.

    Comments are dropped before brace counting so a ``}`` inside a comment cannot close a block.
    A header is the text preceding ``{`` on its own line: carrying it across lines would glue an
    attribute (`name = "open"`) onto the next block's header and hide every nested `ingress`.
    """
    blocks: List[Tuple[str, int, int, int]] = []
    stack: List[Tuple[str, int, int]] = []
    for lineno, raw in enumerate(source.splitlines(), start=1):
        line = re.sub(r"#.*$|//.*$", "", raw)
        pending: List[str] = []
        for part in re.split(r"([{}])", line):
            if part == "{":
                stack.append(("".join(pending).strip(), lineno, lineno))
                pending = []
            elif part == "}":
                if stack:
                    header, start_line, body_start = stack.pop()
                    blocks.append((header, start_line, body_start, lineno))
                pending = []
            elif part.strip():
                pending.append(part)
    return blocks


def _body_lines(source_lines: Sequence[str], body_start: int, body_end: int) -> List[Tuple[int, str]]:
    return [(lineno, source_lines[lineno - 1])
            for lineno in range(body_start, min(body_end, len(source_lines)) + 1)]


def _terraform_exposure(file_path: str, source: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = source.splitlines()
    blocks = _hcl_blocks(source)
    resources: List[Tuple[str, str, int, int, int]] = []
    for header, header_line, body_start, body_end in blocks:
        match = _TF_RESOURCE_RE.match(header + " {")
        if match:
            resources.append((match.group(1), match.group(2), header_line, body_start, body_end))
    for kind, name, _header_line, body_start, body_end in resources:
        body = _body_lines(lines, body_start, body_end)
        if kind in ("aws_s3_bucket", "aws_s3_bucket_acl"):
            for lineno, text in body:
                attr = _TF_ATTR_RE.match(text)
                if not attr or attr.group(1) != "acl":
                    continue
                strings = _TF_STRING_RE.findall(attr.group(2))
                if any(value.strip().lower() in PUBLIC_ACLS for value in strings):
                    findings.append(_finding(
                        file_path, lineno, "CWE-732", "IAC_PUBLIC_EXPOSURE", "HIGH",
                        f'{kind}.{name} sets acl = "{strings[0]}", exposing the bucket to anonymous'
                        ' readers. Set acl = "private" and grant access through a bucket policy'))
        elif kind == "aws_security_group":
            for header, ingress_line, ingress_start, ingress_end in blocks:
                if header.split()[0:1] != ["ingress"]:
                    continue
                if not (body_start <= ingress_line and ingress_end <= body_end):
                    continue
                ingress_body = _body_lines(lines, ingress_start, ingress_end)
                ports: List[int] = []
                world: List[int] = []
                for lineno, text in ingress_body:
                    attr = _TF_ATTR_RE.match(text)
                    if not attr:
                        continue
                    key, value = attr.group(1), attr.group(2)
                    if key in ("from_port", "to_port"):
                        try:
                            ports.append(int(value.strip().strip('"')))
                        except ValueError:
                            continue
                    elif key in ("cidr_blocks", "ipv6_cidr_blocks"):
                        if any(cidr in WORLD_CIDRS for cidr in _TF_STRING_RE.findall(value)):
                            world.append(lineno)
                if not world or len(ports) < 2:
                    continue
                low, high = min(ports), max(ports)
                if not any(low <= port <= high for port in ADMIN_PORTS):
                    continue
                for lineno in world:
                    findings.append(_finding(
                        file_path, lineno, "CWE-732", "IAC_PUBLIC_EXPOSURE", "CRITICAL",
                        f"aws_security_group.{name} opens ports {low}-{high} to 0.0.0.0/0, which"
                        " exposes SSH/RDP to the whole internet. Restrict cidr_blocks to an internal"
                        " range such as 10.0.0.0/8 or a bastion address"))
    return findings


def audit_iac_security_files(files: Dict[str, str]) -> List[Dict[str, Any]]:
    """Audit workflows, Kubernetes manifests and Terraform. CWE-1357 is not emitted here."""
    findings: List[Dict[str, Any]] = []
    for file_path in sorted(files):
        source = files[file_path]
        if is_terraform_path(file_path):
            findings.extend(_terraform_exposure(file_path, source))
            continue
        if not str(file_path).lower().endswith(WORKFLOW_SUFFIXES):
            continue
        # Discovery offers every YAML document in a tree, so parse only the two shapes a rule can
        # read: a workflow by path, a workload manifest by content. An unrelated config is skipped
        # without building a node per line.
        if is_workflow_yaml_path(file_path):
            root = yaml_lite.parse(source)
            raw_lines = source.splitlines()
            findings.extend(_gha_script_injection(file_path, root, raw_lines))
            findings.extend(_gha_permissions(file_path, root, raw_lines))
        elif is_kubernetes_manifest(source):
            findings.extend(_kubernetes_privileges(file_path, yaml_lite.parse(source)))
    return sorted(findings, key=lambda item: (item["file"], item["line"], item["cwe"]))