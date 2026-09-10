"""
validation/sigma_validator.py + yara_validator.py
Validation loop với auto-fix cho cả Sigma và YARA.
"""
import re
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
# SIGMA VALIDATOR
# ═══════════════════════════════════════════════════════════

@dataclass
class SigmaValidationResult:
    valid: bool
    rule_yaml: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    fixed_yaml: Optional[str] = None
    attempts: int = 1

    @property
    def final_yaml(self) -> str:
        return self.fixed_yaml if self.fixed_yaml else self.rule_yaml


class SigmaValidator:
    """
    Validate Sigma rules với pySigma.
    Auto-fix common errors: indentation, missing fields, invalid values.
    """

    REQUIRED_FIELDS = {"title", "logsource", "detection"}
    VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
    VALID_LEVELS = {"critical", "high", "medium", "low", "informational"}
    VALID_LOGSOURCE_CATEGORIES = {
        "process_creation", "network_connection", "file_event", "file_change",
        "file_delete", "file_rename", "registry_add", "registry_delete",
        "registry_event", "registry_set", "registry_rename", "image_load",
        "driver_load", "dns_query", "create_remote_thread", "raw_access_thread",
        "process_access", "pipe_created", "wmi_event", "ps_classic_start",
        "ps_module", "ps_script", "web", "authentication", "antivirus",
        "network_flow", "firewall", "proxy",
    }

    def __init__(self, max_retries: int = 3):
        self.max_retries = max_retries

    def validate(self, rule_yaml: str) -> SigmaValidationResult:
        """Validate Sigma rule, với auto-fix nếu có thể."""
        current_yaml = rule_yaml
        attempts = 0

        while attempts < self.max_retries:
            attempts += 1
            result = self._validate_once(current_yaml, attempts)

            if result.valid:
                return result

            # Thử auto-fix
            fixed = self._auto_fix(current_yaml, result.errors)
            if fixed == current_yaml:
                # Không fix được gì thêm
                break
            current_yaml = fixed
            result.fixed_yaml = fixed

        return SigmaValidationResult(
            valid=False,
            rule_yaml=rule_yaml,
            errors=result.errors,
            fixed_yaml=current_yaml if current_yaml != rule_yaml else None,
            attempts=attempts,
        )

    def _validate_once(self, rule_yaml: str, attempt: int) -> SigmaValidationResult:
        """Single validation pass."""
        errors = []
        warnings = []

        # 1. pySigma validation (nếu installed)
        try:
            from sigma.rule import SigmaRule
            from sigma.exceptions import SigmaError

            try:
                rule = SigmaRule.from_yaml(rule_yaml)
                # pySigma parse thành công
            except SigmaError as e:
                errors.append(f"pySigma: {str(e)}")
            except Exception as e:
                errors.append(f"Parse error: {str(e)}")

        except ImportError:
            # pySigma không có → dùng basic YAML + manual check
            warnings.append("pySigma not installed, using basic validation")

        # 2. Basic YAML structure check
        yaml_errors = self._check_yaml_structure(rule_yaml)
        errors.extend(yaml_errors)

        # 3. Field validation
        field_warnings = self._check_fields(rule_yaml)
        warnings.extend(field_warnings)

        return SigmaValidationResult(
            valid=len(errors) == 0,
            rule_yaml=rule_yaml,
            errors=errors,
            warnings=warnings,
            attempts=attempt,
        )

    def _check_yaml_structure(self, rule_yaml: str) -> list[str]:
        """Check YAML syntax và required fields."""
        errors = []
        try:
            import yaml
            try:
                parsed = yaml.safe_load(rule_yaml)
            except yaml.YAMLError as e:
                return [f"Invalid YAML: {e}"]

            if not isinstance(parsed, dict):
                return ["Rule must be a YAML mapping"]

            # Check required fields
            for field in self.REQUIRED_FIELDS:
                if field not in parsed:
                    errors.append(f"Missing required field: '{field}'")

            # Check status value
            if "status" in parsed and parsed["status"] not in self.VALID_STATUS:
                errors.append(
                    f"Invalid status '{parsed['status']}'. "
                    f"Must be one of: {', '.join(self.VALID_STATUS)}"
                )

            # Check level value
            if "level" in parsed and parsed["level"] not in self.VALID_LEVELS:
                errors.append(
                    f"Invalid level '{parsed['level']}'. "
                    f"Must be one of: {', '.join(self.VALID_LEVELS)}"
                )

            # Check logsource
            if "logsource" in parsed:
                ls = parsed["logsource"]
                if isinstance(ls, dict):
                    category = ls.get("category", "")
                    if category and category not in self.VALID_LOGSOURCE_CATEGORIES:
                        errors.append(
                            f"Unknown logsource category: '{category}'. "
                            f"Consider using: process_creation, network_connection, file_event, etc."
                        )

        except Exception as e:
            errors.append(f"Validation error: {e}")

        return errors

    def _check_fields(self, rule_yaml: str) -> list[str]:
        """Check best practices - returns warnings."""
        warnings = []
        try:
            import yaml
            parsed = yaml.safe_load(rule_yaml)
            if not isinstance(parsed, dict):
                return warnings

            # Check for UUID
            if "id" not in parsed:
                warnings.append("Missing 'id' field (UUID recommended)")

            # Check for description
            if "description" not in parsed:
                warnings.append("Missing 'description' field")

            # Check tags format
            tags = parsed.get("tags", [])
            for tag in tags:
                if not isinstance(tag, str):
                    warnings.append(f"Tag should be string: {tag}")
                elif not (tag.startswith("attack.") or tag.startswith("detection.")):
                    warnings.append(f"Unusual tag prefix: {tag}")

        except Exception:
            pass

        return warnings

    def _auto_fix(self, rule_yaml: str, errors: list[str]) -> str:
        """Auto-fix common errors."""
        fixed = rule_yaml

        for error in errors:
            # Fix: add missing status
            if "Missing required field: 'status'" in error:
                if "status:" not in fixed:
                    fixed = fixed.replace(
                        "title:",
                        "title:",
                        1,
                    )
                    # Thêm status sau title line
                    lines = fixed.split("\n")
                    for i, line in enumerate(lines):
                        if line.strip().startswith("title:"):
                            lines.insert(i + 1, "status: experimental")
                            break
                    fixed = "\n".join(lines)

            # Fix: invalid status → experimental
            if "Invalid status" in error:
                fixed = re.sub(
                    r'^status:\s*.+$',
                    "status: experimental",
                    fixed,
                    flags=re.MULTILINE,
                )

            # Fix: invalid level → medium
            if "Invalid level" in error:
                fixed = re.sub(
                    r'^level:\s*.+$',
                    "level: medium",
                    fixed,
                    flags=re.MULTILINE,
                )

            # Fix: markdown code blocks (LLM thường thêm ```yaml)
            if "Invalid YAML" in error or "Parse error" in error:
                fixed = re.sub(r'^```(?:yaml|yml)?\s*\n', '', fixed, flags=re.MULTILINE)
                fixed = re.sub(r'\n```\s*$', '', fixed, flags=re.MULTILINE)
                fixed = fixed.strip()

        return fixed

    def export_to_siem(
        self,
        rule_yaml: str,
        backend: str = "splunk",
    ) -> Optional[str]:
        """Convert Sigma rule sang SIEM query."""
        try:
            from sigma.rule import SigmaRule
            from sigma.collection import SigmaCollection

            rule = SigmaRule.from_yaml(rule_yaml)
            collection = SigmaCollection([rule])

            if backend == "splunk":
                from sigma.backends.splunk import SplunkBackend
                be = SplunkBackend()
            elif backend == "elasticsearch":
                from sigma.backends.elasticsearch import LuceneBackend
                be = LuceneBackend()
            else:
                logger.warning(f"Unknown backend: {backend}")
                return None

            queries = be.convert(collection)
            return queries[0] if queries else None

        except ImportError as e:
            logger.warning(f"Backend not installed: {e}")
            return None
        except Exception as e:
            logger.error(f"SIEM conversion error: {e}")
            return None


# ═══════════════════════════════════════════════════════════
# YARA VALIDATOR
# ═══════════════════════════════════════════════════════════

YARA_MODULES_WHITELIST = {
    "pe", "math", "cuckoo", "magic", "hash", "dotnet", "elf", "macho", "time"
}


@dataclass
class YARAValidationResult:
    valid: bool
    rule_text: str
    errors: list[str] = field(default_factory=list)
    fixed_rule: Optional[str] = None
    attempts: int = 1

    @property
    def final_rule(self) -> str:
        return self.fixed_rule if self.fixed_rule else self.rule_text


class YARAValidator:
    """
    Validate YARA rules với yara-python.
    Auto-fix: inject missing imports, fix common syntax issues.
    """

    def __init__(self, max_retries: int = 10):
        self.max_retries = max_retries

    def validate(self, rule_text: str) -> YARAValidationResult:
        """Validate + auto-fix YARA rule."""
        current_rule = rule_text
        attempts = 0
        last_error = ""

        while attempts < self.max_retries:
            attempts += 1
            try:
                import yara
                yara.compile(source=current_rule)
                # Compile thành công
                return YARAValidationResult(
                    valid=True,
                    rule_text=rule_text,
                    fixed_rule=current_rule if current_rule != rule_text else None,
                    attempts=attempts,
                )

            except Exception as e:
                error_msg = str(e)
                last_error = error_msg

                # Auto-fix: undefined identifier → inject import
                match = re.search(r'undefined identifier "(\w+)"', error_msg)
                if match:
                    missing = match.group(1)
                    if missing in YARA_MODULES_WHITELIST:
                        current_rule = self._inject_import(current_rule, missing)
                        continue

                # Auto-fix: markdown code blocks
                if "```" in current_rule:
                    current_rule = re.sub(r'^```(?:yara)?\s*\n', '', current_rule, flags=re.MULTILINE)
                    current_rule = re.sub(r'\n```\s*$', '', current_rule, flags=re.MULTILINE)
                    current_rule = current_rule.strip()
                    continue

                # Không fix được → break
                break

            except ImportError:
                return YARAValidationResult(
                    valid=False,
                    rule_text=rule_text,
                    errors=["yara-python not installed: pip install yara-python"],
                    attempts=attempts,
                )

        return YARAValidationResult(
            valid=False,
            rule_text=rule_text,
            errors=[last_error],
            fixed_rule=current_rule if current_rule != rule_text else None,
            attempts=attempts,
        )

    def _inject_import(self, rule_text: str, module: str) -> str:
        """Inject import statement nếu chưa có."""
        import_stmt = f'import "{module}"'
        if import_stmt not in rule_text:
            return f'{import_stmt}\n\n{rule_text}'
        return rule_text


# ── Quick test ───────────────────────────────────────────────
if __name__ == "__main__":
    print("=== Sigma Validator Test ===")
    sigma_validator = SigmaValidator()

    # Test rule với errors
    bad_sigma = """
title: Test Certutil Download
status: invalid_status
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains: '-urlcache'
    condition: selection
level: critical
"""
    result = sigma_validator.validate(bad_sigma)
    print(f"Valid: {result.valid}")
    print(f"Errors: {result.errors}")
    print(f"Warnings: {result.warnings}")
    if result.fixed_yaml:
        print(f"Fixed YAML:\n{result.fixed_yaml}")

    print("\n=== YARA Validator Test ===")
    yara_validator = YARAValidator()

    bad_yara = '''
rule TestMalware {
    meta:
        description = "Test rule"
    strings:
        $pe_header = { 4D 5A }
        $sus_string = "malicious" nocase
    condition:
        $pe_header at 0 and $sus_string and
        pe.entry_point > 0
}
'''
    result = yara_validator.validate(bad_yara)
    print(f"Valid: {result.valid}")
    print(f"Errors: {result.errors}")
    print(f"Attempts: {result.attempts}")
    if result.fixed_rule:
        print(f"Fixed rule:\n{result.fixed_rule[:200]}...")
