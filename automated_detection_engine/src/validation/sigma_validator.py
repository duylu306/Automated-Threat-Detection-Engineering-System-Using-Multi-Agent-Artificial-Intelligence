"""
src/validation/sigma_validator.py
──────────────────────────────────
Validate Sigma rules dung pySigma.
Auto-fix cac loi pho bien va score quality.
"""
import re
import logging
import uuid
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ValidationIssue:
    severity: str    # "error" | "warning" | "info"
    field: str
    message: str
    fix_hint: str = ""


@dataclass
class SigmaValidationResult:
    valid: bool
    score: int = 0          # 0-10
    issues: list[ValidationIssue] = field(default_factory=list)
    fixed_yaml: str = ""
    original_yaml: str = ""
    error_message: str = ""


class SigmaValidator:
    """
    Validate va auto-fix Sigma rules.

    Usage:
        validator = SigmaValidator()
        result = validator.validate(rule_yaml)
        if result.valid:
            print("Rule OK, score:", result.score)
        else:
            print("Issues:", result.issues)
    """

    REQUIRED_FIELDS = ["title", "logsource", "detection"]
    VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
    VALID_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
    VALID_LOGSOURCE_CATEGORIES = {
        "process_creation", "network_connection", "file_event",
        "registry_event", "dns_query", "image_load", "driver_load",
        "pipe_created", "process_access", "web", "authentication",
        "ps_script", "ps_module", "wmi_event",
    }

    def validate(self, rule_yaml: str) -> SigmaValidationResult:
        """
        Validate mot Sigma rule YAML.
        Thu pySigma truoc, fallback sang manual parsing.
        """
        result = SigmaValidationResult(
            valid=False,
            original_yaml=rule_yaml,
        )

        if not rule_yaml or not rule_yaml.strip():
            result.issues.append(ValidationIssue(
                severity="error",
                field="general",
                message="Rule YAML is empty",
            ))
            return result

        # Buoc 1: Try pySigma validation
        pysigma_ok, pysigma_error = self._validate_with_pysigma(rule_yaml)

        if not pysigma_ok:
            result.error_message = pysigma_error
            # Auto-fix thu
            fixed = self._auto_fix(rule_yaml, pysigma_error)
            if fixed != rule_yaml:
                # Thu lai sau khi fix
                pysigma_ok2, _ = self._validate_with_pysigma(fixed)
                if pysigma_ok2:
                    rule_yaml = fixed
                    result.fixed_yaml = fixed
                    result.issues.append(ValidationIssue(
                        severity="info",
                        field="general",
                        message="Auto-fixed successfully",
                    ))
                    pysigma_ok = True

        if not pysigma_ok and result.error_message:
            result.issues.append(ValidationIssue(
                severity="error",
                field="syntax",
                message=result.error_message,
                fix_hint="Check YAML indentation and field names",
            ))

        # Buoc 2: Manual checks (chay du dù pySigma pass)
        import yaml
        try:
            parsed = yaml.safe_load(rule_yaml)
            if not isinstance(parsed, dict):
                result.issues.append(ValidationIssue(
                    severity="error", field="general",
                    message="Rule must be a YAML dict",
                ))
                return result

            manual_issues = self._manual_checks(parsed)
            result.issues.extend(manual_issues)

        except yaml.YAMLError as e:
            result.issues.append(ValidationIssue(
                severity="error", field="yaml",
                message=f"YAML parse error: {e}",
            ))
            return result

        # Buoc 3: Score
        error_count = sum(1 for i in result.issues if i.severity == "error")
        warning_count = sum(1 for i in result.issues if i.severity == "warning")

        result.valid = pysigma_ok and error_count == 0
        result.score = max(0, 10 - (error_count * 3) - (warning_count * 1))
        result.fixed_yaml = result.fixed_yaml or rule_yaml

        return result

    def _validate_with_pysigma(self, rule_yaml: str) -> tuple[bool, str]:
        """Thu validate voi pySigma library."""
        try:
            from sigma.collection import SigmaCollection
            from sigma.exceptions import SigmaError
            SigmaCollection.from_yaml(rule_yaml)
            return True, ""
        except Exception as e:
            return False, str(e)

    def _auto_fix(self, rule_yaml: str, error: str) -> str:
        """Auto-fix cac loi pho bien."""
        fixed = rule_yaml

        # Fix 1: Missing UUID
        if "id:" not in fixed:
            fixed = fixed.replace(
                "title:", f"id: {uuid.uuid4()}\ntitle:", 1
            )

        # Fix 2: Missing status
        if "status:" not in fixed:
            fixed += "\nstatus: experimental"

        # Fix 3: Missing level
        if "level:" not in fixed:
            fixed += "\nlevel: medium"

        # Fix 4: Invalid level
        level_match = re.search(r"level:\s*(\w+)", fixed)
        if level_match:
            level = level_match.group(1).lower()
            if level not in self.VALID_LEVELS:
                fixed = re.sub(r"level:\s*\w+", "level: medium", fixed)

        # # Fix 5: Missing condition
        # if "detection:" in fixed and "condition:" not in fixed:
        #     # Tim selection block va them condition
        #     fixed = re.sub(
        #         r"(detection:\s*\n(?:\s+\w+:.*\n)+)",
        #         r"\1    condition: selection\n",
        #         fixed
        #     )

        return fixed

    def _manual_checks(self, parsed: dict) -> list[ValidationIssue]:
        """Kiem tra thu cong cac best practices."""
        issues = []

        # Check required fields
        for req in self.REQUIRED_FIELDS:
            if req not in parsed:
                issues.append(ValidationIssue(
                    severity="error",
                    field=req,
                    message=f"Required field '{req}' is missing",
                    fix_hint=f"Add '{req}:' field to the rule",
                ))

        # Check level
        level = parsed.get("level", "")
        if level and level not in self.VALID_LEVELS:
            issues.append(ValidationIssue(
                severity="warning",
                field="level",
                message=f"Invalid level '{level}'",
                fix_hint=f"Use one of: {self.VALID_LEVELS}",
            ))

        # Check status
        status = parsed.get("status", "")
        if status and status not in self.VALID_STATUSES:
            issues.append(ValidationIssue(
                severity="warning",
                field="status",
                message=f"Invalid status '{status}'",
            ))

        # Check ATT&CK tags
        tags = parsed.get("tags", [])
        has_attck_tag = any(str(t).startswith("attack.") for t in tags)
        if not has_attck_tag:
            issues.append(ValidationIssue(
                severity="warning",
                field="tags",
                message="No ATT&CK tags found",
                fix_hint="Add tags like: attack.t1059 or attack.execution",
            ))

        # Check logsource
        logsource = parsed.get("logsource", {})
        if isinstance(logsource, dict):
            category = logsource.get("category", "")
            if category and category not in self.VALID_LOGSOURCE_CATEGORIES:
                issues.append(ValidationIssue(
                    severity="warning",
                    field="logsource.category",
                    message=f"Unusual logsource category: '{category}'",
                ))

        # Check detection condition
        detection = parsed.get("detection", {})
        if isinstance(detection, dict) and "condition" not in detection:
            issues.append(ValidationIssue(
                severity="error",
                field="detection.condition",
                message="Missing 'condition' in detection block",
                fix_hint="Add: condition: selection",
            ))

        # Anti-pattern: wildcard abuse
        rule_str = str(parsed)
        if rule_str.count("'*") > 5 or rule_str.count("*'") > 5:
            issues.append(ValidationIssue(
                severity="warning",
                field="detection",
                message="Excessive wildcard usage may cause high FP rate",
                fix_hint="Use contains/endswith modifiers instead of leading wildcards",
            ))

        return issues
