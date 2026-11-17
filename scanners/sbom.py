"""CycloneDX 1.5 JSON SBOM export -- stdlib only, built from the same parse the audit used.

The inventory and the findings come from one pass over the manifests, so the bill of materials
cannot disagree with the report: every `affects.ref` resolves to a component that is actually
listed, and every component carries the manifest line it was declared on.

Two honesty rules shape the document:

* A component carries a `version` only when the manifest proves exactly one. `^4.17.20` allows a
  range, so it is inventoried as a version-less purl rather than as a guess at whichever release
  a resolver happened to pick. A version-less purl is legal CycloneDX; a fabricated version is not.
* A vulnerability's CWE, severity and fix are read per CVE from the advisory index, not copied
  from the finding's primary label. One pin can carry several advisories with different root
  weaknesses and different fixes, and `requests==2.30.0` must not report CVE-2024-35195's fix as
  the remedy for CVE-2023-32681.

Reachability travels as a property, so a consumer can filter dormant lockfile entries the same
way the table does.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .cve_index import advisories_for, compare_versions, parse_version
from .sca_scanner import CATEGORY as SCA_CATEGORY

__all__ = ["build_sbom", "component_purl", "SPEC_VERSION"]

SPEC_VERSION = "1.5"
TOOL_VENDOR = "TCS"
TOOL_NAME = "time-code-security"
TOOL_VERSION = "1.0.0"

_SEVERITY_TEXT = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_CWE_NUMBER = re.compile(r"CWE-(\d+)")
NVD_URL = "https://nvd.nist.gov/vuln/detail/"


def component_purl(ecosystem: str, name: str, version: Optional[str] = None) -> str:
    """A package URL. An npm scope's leading '@' is percent-encoded so it stays one path segment."""
    spelled = name.replace("@", "%40", 1) if name.startswith("@") else name
    return "pkg:%s/%s" % (ecosystem, spelled) + ("@" + version if version else "")


def _advisory_facts(ecosystem: str, package: str, cve: str,
                    version: Optional[str]) -> Tuple[List[int], str, str, str]:
    """(CWE numbers, severity, summary, upgrade target) for one CVE on one component."""
    records = [item for item in advisories_for(ecosystem, package) if item[0] == cve]
    cwes = {1395}
    severity = "LOW"
    summary = ""
    current = parse_version(version) if version else None
    target: Optional[str] = None
    target_key = None
    for item in records:
        hit = _CWE_NUMBER.match(item[1])
        if hit:
            cwes.add(int(hit.group(1)))
        if _SEVERITY_RANK.get(item[2], 0) > _SEVERITY_RANK.get(severity, 0):
            severity = item[2]
        if not summary:
            summary = item[5]
        fixed = parse_version(item[3])
        if fixed is None:
            continue
        # With a known version the remedy is the nearest fix above it on its own branch, not the
        # newest fix across every branch: ws 7.5.9 is remedied by 7.5.10, not by 8.17.1.
        if current is not None and compare_versions(fixed, current) <= 0:
            continue
        if target_key is None or compare_versions(fixed, target_key) < 0:
            target, target_key = item[3], fixed
    if target is None and records:
        target = max((item[3] for item in records), key=lambda text: parse_version(text) or ())
    return sorted(cwes), _SEVERITY_TEXT.get(severity, "unknown"), summary, target or ""


def build_sbom(components: List[Dict[str, Any]], findings: List[Dict[str, Any]], *,
               root_name: str = "target", timestamp: Optional[str] = None,
               serial_number: Optional[str] = None) -> Dict[str, Any]:
    """A CycloneDX 1.5 document. `findings` is the complete emission set, not the display rows."""
    meta: Dict[str, Dict[str, Any]] = {}
    locations: Dict[str, List[str]] = {}

    def declare(entry: Dict[str, Any]) -> str:
        purl = component_purl(entry["ecosystem"], entry["name"], entry.get("version"))
        if purl not in meta:
            meta[purl] = entry
            locations[purl] = []
        where = "%s:%s" % (entry["file"], entry["line"])
        if where not in locations[purl]:
            locations[purl].append(where)
        return purl

    for entry in components:
        declare(entry)

    index = {(entry["file"], entry["line"], entry["name"]): entry for entry in components}
    records: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for finding in findings:
        if finding.get("category") != SCA_CATEGORY:
            continue
        entry = index.get((finding["file"], finding["line"], finding["package"]))
        if entry is None:
            entry = {"ecosystem": finding["ecosystem"], "name": finding["package"],
                     "version": None, "spec": finding.get("spec", ""),
                     "file": finding["file"], "line": finding["line"]}
        purl = declare(entry)
        for cve in finding.get("cves") or [finding.get("cve")]:
            if not cve:
                continue
            key = (cve, purl)
            record = records.get(key)
            if record is None:
                cwes, severity, summary, fixed = _advisory_facts(
                    entry["ecosystem"], entry["name"], cve, entry.get("version"))
                record = {"cve": cve, "purl": purl, "cwes": cwes, "severity": severity,
                          "summary": summary, "fixed": fixed, "locations": [],
                          "reachability": "UNREACHABLE_MANIFEST_ONLY", "confidence": "LOW"}
                records[key] = record
            # Reachability is a proof about the code, and one proof anywhere is enough: the
            # upgrade never runs backwards when a second manifest declares the same coordinate.
            if finding.get("reachability") == "REACHABLE":
                record["reachability"] = "REACHABLE"
                record["confidence"] = finding.get("confidence", "HIGH")
            where = "%s:%s" % (finding["file"], finding["line"])
            if where not in record["locations"]:
                record["locations"].append(where)

    root_ref = "root:%s" % (root_name or "target")
    component_nodes = []
    for purl, entry in meta.items():
        node: Dict[str, Any] = {"type": "library", "bom-ref": purl, "name": entry["name"],
                                "purl": purl}
        if entry.get("version"):
            node["version"] = entry["version"]
        properties = [{"name": "tcs:ecosystem", "value": entry["ecosystem"]},
                      {"name": "tcs:spec", "value": str(entry.get("spec") or "")}]
        properties.extend({"name": "tcs:manifest", "value": where} for where in locations[purl])
        node["properties"] = properties
        component_nodes.append(node)

    vulnerability_nodes = []
    for (cve, purl), record in sorted(records.items()):
        properties = [{"name": "tcs:reachability", "value": record["reachability"]},
                      {"name": "tcs:confidence", "value": record["confidence"]}]
        if record["fixed"]:
            properties.append({"name": "tcs:fixed_version", "value": record["fixed"]})
        properties.extend({"name": "tcs:manifest", "value": where} for where in record["locations"])
        node: Dict[str, Any] = {
            "bom-ref": "vuln:%s:%s" % (cve, purl),
            "id": cve,
            "source": {"name": "NVD", "url": NVD_URL + cve},
            "cwes": record["cwes"],
            "ratings": [{"severity": record["severity"], "method": "other"}],
            "description": record["summary"],
            "affects": [{"ref": purl}],
            "properties": properties,
        }
        if record["fixed"]:
            node["recommendation"] = "Upgrade to version %s or later." % record["fixed"]
        vulnerability_nodes.append(node)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial_number or "urn:uuid:%s" % uuid.uuid4(),
        "version": 1,
        "metadata": {
            "timestamp": timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"vendor": TOOL_VENDOR, "name": TOOL_NAME, "version": TOOL_VERSION}],
            "component": {"type": "application", "bom-ref": root_ref,
                          "name": root_name or "target"},
        },
        "components": component_nodes,
        "vulnerabilities": vulnerability_nodes,
        "dependencies": [{"ref": root_ref, "dependsOn": sorted(meta)}]
                        + [{"ref": purl, "dependsOn": []} for purl in sorted(meta)],
    }