"""
src/validation/yara_validator.py
─────────────────────────────────
Validate va auto-fix YARA rules dung yara-python.
Auto-inject missing imports (pe, math, hash...).
"""
import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

YARA_MODULES_WHITELIST = {"pe", "math", "cuckoo", "magic", "hash", "dotnet", "elf", "macho"}


@dataclass
class YaraValidationResult:
    valid: bool
    score: int = 0           # 0-10
    rule_text: str = ""
    error_message: str = ""
    attempts: int = 0
    fixes_applied: list[str] = field(default_factory=list)


class YaraValidator:
    """
    Validate va auto-fix YARA rules.

    Usage:
        validator = YaraValidator()
        result = validator.validate(yara_rule_text)
        if result.valid:
            print("YARA OK, score:", result.score)
    """

    def __init__(self, max_retries: int = 10):
        self.max_retries = max_retries

    def validate(self, raw_rule: str) -> YaraValidationResult:
        """Validate + auto-fix YARA rule trong vong lap."""
        try:
            import yara
        except ImportError:
            raise ImportError("yara-python not installed. Run: pip install yara-python")

        if not raw_rule or not raw_rule.strip():
            return YaraValidationResult(
                valid=False,
                error_message="Empty YARA rule",
            )

        current = raw_rule
        fixes_applied = []
        attempts = 0

        while attempts < self.max_retries:
            try:
                yara.compile(source=current)
                # Compile thanh cong!
                score = self._score_rule(current)
                return YaraValidationResult(
                    valid=True,
                    score=score,
                    rule_text=current,
                    attempts=attempts + 1,
                    fixes_applied=fixes_applied,
                )

            except yara.SyntaxError as e:
                error_msg = str(e)
                attempts += 1

                # Auto-fix: undefined identifier (missing import)
                match = re.search(r'undefined identifier "(\w+)"', error_msg)
                if match:
                    missing = match.group(1)
                    if missing in YARA_MODULES_WHITELIST:
                        current = self._inject_import(current, missing)
                        fix = f"Injected: import \"{missing}\""
                        fixes_applied.append(fix)
                        logger.info(fix)
                        continue

                # Auto-fix: rule name co ky tu dac biet
                if "invalid identifier" in error_msg.lower():
                    current = self._fix_rule_name(current)
                    fixes_applied.append("Fixed rule name")
                    continue

                # Auto-fix: strings block thieu $
                if "syntax error" in error_msg.lower() and "strings" in current:
                    current = self._fix_string_names(current)
                    fixes_applied.append("Fixed string names")
                    continue

                # Loi khong tu fix duoc
                return YaraValidationResult(
                    valid=False,
                    rule_text=current,
                    error_message=f"Irrecoverable error: {error_msg}",
                    attempts=attempts,
                    fixes_applied=fixes_applied,
                )

            except Exception as e:
                return YaraValidationResult(
                    valid=False,
                    rule_text=current,
                    error_message=str(e),
                    attempts=attempts,
                    fixes_applied=fixes_applied,
                )

        return YaraValidationResult(
            valid=False,
            rule_text=current,
            error_message=f"Exceeded max retries ({self.max_retries})",
            attempts=attempts,
            fixes_applied=fixes_applied,
        )

    def _inject_import(self, rule: str, module: str) -> str:
        """Them import neu chua co."""
        import_stmt = f'import "{module}"'
        if import_stmt not in rule:
            return f'{import_stmt}\n\n{rule}'
        return rule

    def _fix_rule_name(self, rule: str) -> str:
        """Sua rule name co ky tu khong hop le."""
        def clean_name(m):
            name = m.group(1)
            name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
            if name[0].isdigit():
                name = "rule_" + name
            return f"rule {name} {{"
        return re.sub(r"rule\s+(\S+)\s*\{", clean_name, rule)

    def _fix_string_names(self, rule: str) -> str:
        """Dam bao tat ca strings bat dau bang $."""
        lines = rule.split("\n")
        fixed = []
        in_strings = False
        for line in lines:
            stripped = line.strip()
            if stripped == "strings:":
                in_strings = True
            elif stripped.startswith("condition:") or stripped == "}":
                in_strings = False

            if in_strings and "=" in line and not stripped.startswith("$"):
                indent = len(line) - len(line.lstrip())
                line = " " * indent + "$" + line.lstrip()

            fixed.append(line)
        return "\n".join(fixed)

    def _score_rule(self, rule: str) -> int:
        """Score YARA rule quality 0-10."""
        score = 5  # base score neu compile duoc

        # +1: co meta block
        if "meta:" in rule:
            score += 1

        # +1: co description trong meta
        if "description" in rule and "meta:" in rule:
            score += 1

        # +1: dung modifiers dung cach
        if any(m in rule for m in ["nocase", "wide", "ascii", "fullword"]):
            score += 1

        # +1: co PE check
        if "uint16(0) == 0x5A4D" in rule or "pe.is_pe" in rule:
            score += 1

        # -1: strings qua ngan (de FP)
        short_strings = re.findall(r'"(.{1,3})"', rule)
        if len(short_strings) > 3:
            score -= 1

        # -1: khong co strings block
        if "strings:" not in rule:
            score -= 1

        return max(0, min(10, score))
