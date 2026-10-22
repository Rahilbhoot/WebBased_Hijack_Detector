"""Rule evaluation engine for the Browser Hijack Detector.

Pure-function detection engine supporting YAML rule loading, condition matching,
whitelist suppression, score calculation, and human-readable explanation formatting.
Designed to run identically in the Windows agent and in AWS Lambda.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

from agent.models import NormalizedEvent

logger = logging.getLogger("agent.rule_engine")


@dataclass
class RuleCondition:
    """Represents a single match condition against a field in NormalizedEvent."""

    field: str
    match: str  # contains, not_contains, regex, equals, not_equals, starts_with, ends_with, in_list
    values: List[str] = dataclasses.field(default_factory=list)

    def evaluate(self, event_data: Dict[str, Any]) -> bool:
        """Evaluates whether the condition matches the event data."""
        raw_val = event_data.get(self.field)
        val_str = str(raw_val).strip() if raw_val is not None else ""

        # exists / not_exists checks
        if self.match == "exists":
            return bool(raw_val is not None and val_str)
        if self.match == "not_exists":
            return raw_val is None or not val_str

        # If the field is missing/empty and we are checking positive match criteria, return False
        if not val_str:
            return self.match in ("not_contains", "not_equals")

        val_lower = val_str.lower()

        if self.match == "contains":
            return any(target.lower() in val_lower for target in self.values)

        elif self.match == "not_contains":
            return all(target.lower() not in val_lower for target in self.values)

        elif self.match == "equals":
            return any(target.lower() == val_lower for target in self.values)

        elif self.match == "not_equals":
            return all(target.lower() != val_lower for target in self.values)

        elif self.match == "starts_with":
            return any(val_lower.startswith(target.lower()) for target in self.values)

        elif self.match == "ends_with":
            return any(val_lower.endswith(target.lower()) for target in self.values)

        elif self.match == "in_list":
            return any(target.lower() == val_lower for target in self.values)

        elif self.match == "regex":
            for pattern in self.values:
                try:
                    if re.search(pattern, val_str, re.IGNORECASE):
                        return True
                except re.error as err:
                    logger.warning(f"Invalid regex pattern '{pattern}': {err}")
            return False

        logger.warning(f"Unknown match operator '{self.match}'")
        return False


@dataclass
class DetectionRule:
    """A single security detection rule."""

    id: str
    name: str
    description: str
    event_type: List[str]
    conditions: List[RuleCondition]
    base_score: int
    mitre_ids: List[str] = dataclasses.field(default_factory=list)
    explanation_template: str = ""

    def matches(self, event: NormalizedEvent) -> bool:
        """Checks if a normalized event matches this rule's event type and all conditions."""
        if self.event_type and event.type not in self.event_type:
            return False

        event_dict = event.to_dict()
        for cond in self.conditions:
            if not cond.evaluate(event_dict):
                return False

        return True

    def format_explanation(self, event: NormalizedEvent) -> str:
        """Generates a plain-English explanation of why this rule fired."""
        if not self.explanation_template:
            return f"Event matched rule {self.id}: {self.name}."

        event_dict = event.to_dict()
        # Replace empty values with 'N/A' for formatting
        safe_dict = {
            k: (v if v is not None and str(v).strip() else "N/A") for k, v in event_dict.items()
        }

        try:
            return self.explanation_template.format(**safe_dict).strip()
        except KeyError as e:
            logger.debug(f"Missing key in explanation template {self.id}: {e}")
            summary = event.process_image or event.file_path or event.type
            return f"{self.name} triggered on {summary}."


@dataclass
class WhitelistConfig:
    """Whitelist configuration for suppressing benign false positives."""

    trusted_paths: List[str] = dataclasses.field(default_factory=list)
    trusted_publishers: List[str] = dataclasses.field(default_factory=list)
    suppressed_rules: Dict[str, List[RuleCondition]] = dataclasses.field(default_factory=dict)

    def is_suppressed(self, event: NormalizedEvent, rule_id: Optional[str] = None) -> bool:
        """Checks if an event or specific rule match should be suppressed by whitelist."""
        # 1. Path whitelist applies to process_image (the executing binary), not target files
        if event.process_image:
            path_norm = event.process_image.replace("/", "\\").lower()
            for pattern in self.trusted_paths:
                pattern_norm = pattern.replace("/", "\\").lower()
                if fnmatch.fnmatch(path_norm, pattern_norm):
                    return True

        # 2. Check rule-specific suppression conditions
        if rule_id and rule_id in self.suppressed_rules:
            event_dict = event.to_dict()
            rule_suppressions = self.suppressed_rules[rule_id]
            # If all suppression conditions for this rule match, suppress it
            if all(cond.evaluate(event_dict) for cond in rule_suppressions):
                return True

        return False


def calculate_severity(score: int) -> str:
    """Maps a numerical score to a severity label (PRD Section 5.3)."""
    if score >= 60:
        return "High"
    elif score >= 30:
        return "Medium"
    return "Low"


class RuleEngine:
    """Main detection engine that evaluates events against rules and whitelist."""

    def __init__(
        self,
        rules_path: Optional[Union[str, Path]] = None,
        whitelist_path: Optional[Union[str, Path]] = None,
    ):
        self.rules: List[DetectionRule] = []
        self.whitelist = WhitelistConfig()

        if rules_path:
            self.load_rules(rules_path)
        if whitelist_path:
            self.load_whitelist(whitelist_path)

    def load_rules(self, rules_path: Union[str, Path]) -> None:
        """Loads and parses detection rules from a YAML file."""
        path = Path(rules_path).resolve()
        if not path.is_file():
            logger.warning(f"Rules file not found at {path}")
            return

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        loaded_rules: List[DetectionRule] = []
        for r in data.get("rules", []):
            try:
                # Handle single string or list for event_type
                evt_type = r.get("event_type", [])
                if isinstance(evt_type, str):
                    evt_types = [evt_type]
                else:
                    evt_types = [str(x) for x in evt_type]

                conditions: List[RuleCondition] = []
                for c in r.get("conditions", []):
                    vals = c.get("values", [])
                    if isinstance(vals, str):
                        vals = [vals]
                    conditions.append(
                        RuleCondition(
                            field=str(c.get("field", "")),
                            match=str(c.get("match", "contains")).lower(),
                            values=[str(v) for v in vals],
                        )
                    )

                loaded_rules.append(
                    DetectionRule(
                        id=str(r.get("id")),
                        name=str(r.get("name")),
                        description=str(r.get("description", "")),
                        event_type=evt_types,
                        conditions=conditions,
                        base_score=int(r.get("base_score", 10)),
                        mitre_ids=[str(m) for m in r.get("mitre_ids", [])],
                        explanation_template=str(r.get("explanation_template", "")),
                    )
                )
            except Exception as e:
                logger.error(f"Error parsing rule {r.get('id')}: {e}")

        self.rules = loaded_rules
        logger.info(f"Loaded {len(self.rules)} detection rules from {path.name}.")

    def load_whitelist(self, whitelist_path: Union[str, Path]) -> None:
        """Loads whitelist suppression configuration from a YAML file."""
        path = Path(whitelist_path).resolve()
        if not path.is_file():
            logger.warning(f"Whitelist file not found at {path}")
            return

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        suppressed_rules: Dict[str, List[RuleCondition]] = {}
        for rule_id, cond_list in data.get("suppressed_rules", {}).items():
            parsed_conds: List[RuleCondition] = []
            for c in cond_list:
                vals = c.get("values", [])
                if isinstance(vals, str):
                    vals = [vals]
                parsed_conds.append(
                    RuleCondition(
                        field=str(c.get("field", "")),
                        match=str(c.get("match", "equals")).lower(),
                        values=[str(v) for v in vals],
                    )
                )
            suppressed_rules[str(rule_id)] = parsed_conds

        self.whitelist = WhitelistConfig(
            trusted_paths=[str(p) for p in data.get("trusted_paths", [])],
            trusted_publishers=[str(p) for p in data.get("trusted_publishers", [])],
            suppressed_rules=suppressed_rules,
        )
        logger.info(f"Loaded whitelist from {path.name}.")

    def evaluate(self, event: NormalizedEvent) -> List[DetectionRule]:
        """Evaluates an event against all active rules, filtering out whitelisted items.

        Returns a list of DetectionRule instances that fired.
        """
        # Overall path whitelist check on process_image
        if self.whitelist.is_suppressed(event):
            logger.debug(f"Event {event.event_id} suppressed by global path whitelist.")
            return []

        matched_rules: List[DetectionRule] = []
        for rule in self.rules:
            if rule.matches(event):
                # Check rule-specific suppression
                if self.whitelist.is_suppressed(event, rule_id=rule.id):
                    logger.debug(
                        f"Rule {rule.id} suppressed by whitelist for event {event.event_id}."
                    )
                    continue
                matched_rules.append(rule)

        return matched_rules
