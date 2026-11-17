"""Modular auxiliary security scanners: containers, CI/IaC and dependency composition.

These run beside the Python AST engine, never inside it. ``ast_scanner.py`` is not imported for
detection here and is not modified by this package; the only shared surface is the finding dict
shape that ``cli._merge_findings`` already consumes.

``iac_auditor`` keeps owning the legacy Dockerfile CWE-250/CWE-269 rows and every CWE-1357
unpinned-action row. The scanners in this package add the Snyk-container and Snyk-IaC rule families
on top, and ``audit_security_files`` suppresses a second CWE-250 on a file the legacy auditor
already booked so one defect is never reported twice.

``sca_scanner`` is the Snyk-Open-Source family: manifests and lockfiles matched against the offline
advisory index in ``cve_index``, then labelled by an import-reachability proof the caller supplies.
It is deliberately separate from ``audit_security_files`` because reachability needs the Python
engine's parsed trees, which only the caller has.

``secret_scanner`` is the Snyk-Code config family: ``.env``, INI, TOML, JSON, YAML and shell
documents carrying a vendor-prefixed or cryptographic credential. ``sbom`` renders the same
manifest parse as a CycloneDX 1.5 document, so the bill of materials and the report cannot drift.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .container_scanner import (
    audit_container_files,
    is_compose_path,
    is_container_path,
    is_dockerfile_name,
)
from .iac_scanner import (
    audit_iac_security_files,
    is_iac_security_path,
    is_kubernetes_manifest,
    is_terraform_path,
    is_workflow_yaml_path,
)
from .sca_scanner import (
    audit_sca_files,
    collect_components,
    is_manifest_path,
    tag_reachability,
)
from .sbom import build_sbom
from .secret_scanner import audit_secret_files, is_secret_path

__all__ = [
    "audit_container_files", "audit_iac_security_files", "audit_security_files",
    "is_container_path", "is_compose_path", "is_dockerfile_name",
    "is_iac_security_path", "is_workflow_yaml_path", "is_terraform_path",
    "is_kubernetes_manifest", "is_aux_security_path",
    "audit_sca_files", "is_manifest_path", "tag_reachability",
    "collect_components", "build_sbom",
    "audit_secret_files", "is_secret_path",
]


def is_aux_security_path(path: str) -> bool:
    """Path-decidable auxiliary security families. Kubernetes needs a content sniff as well."""
    return is_container_path(path) or is_iac_security_path(path)


def audit_security_files(files: Dict[str, str],
                         legacy_findings: Iterable[Dict[str, Any]] = ()) -> List[Dict[str, Any]]:
    """Run both scanners over ``{path: source}`` and return their findings, deterministically."""
    already_root = {item["file"] for item in legacy_findings if item.get("cwe") == "CWE-250"}
    findings = audit_container_files(files, already_root_reported=already_root)
    findings.extend(audit_iac_security_files(files))
    return sorted(findings, key=lambda item: (item["file"], item["line"], item["cwe"]))