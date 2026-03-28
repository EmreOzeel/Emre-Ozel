"""YAML rule loading and suppression engine."""
import os
import yaml
from typing import Dict, Any, List, Optional
from models import Finding

_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")


def load_rules(path: Optional[str] = None) -> Dict[str, Any]:
    """Load detection rules from YAML. Returns merged config dict."""
    if path is None:
        path = os.path.join(_RULES_DIR, "default.yaml")
    with open(path) as f:
        return yaml.safe_load(f)


def load_suppressions(path: Optional[str] = None) -> List[Dict]:
    """Load suppression rules from YAML."""
    if path is None:
        path = os.path.join(_RULES_DIR, "suppression.yaml")
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
            return data.get("suppressions", []) or []
    except FileNotFoundError:
        return []


def get_rule(config: Dict, rule_id: str) -> Optional[Dict]:
    """Lookup a rule by ID."""
    for rule in config.get("rules", []):
        if rule.get("id") == rule_id:
            return rule
    return None


def get_threshold(config: Dict, rule_id: str, key: str, default: Any = None) -> Any:
    """Convenience: get a threshold value from a rule."""
    rule = get_rule(config, rule_id)
    if rule:
        return rule.get("thresholds", {}).get(key, default)
    return default


def apply_suppressions(findings: List[Finding], suppressions: List[Dict],
                        whitelist_ips: List[str]) -> List[Finding]:
    """
    Mark findings as suppressed if they match any suppression rule or whitelist.
    Returns the same list with .suppressed set.
    """
    wl_set = set(whitelist_ips)

    for finding in findings:
        # Whitelist check
        if any(ip in wl_set for ip in finding.affected_hosts):
            finding.suppressed = True
            continue

        # Suppression rule check
        for sup in suppressions:
            if sup.get("rule_id") and sup["rule_id"] != finding.rule_id:
                continue
            src_ip = sup.get("src_ip")
            dst_ip = sup.get("dst_ip")
            if src_ip and src_ip not in finding.affected_hosts:
                continue
            if dst_ip and dst_ip not in finding.affected_hosts:
                continue
            finding.suppressed = True
            break

    return findings
