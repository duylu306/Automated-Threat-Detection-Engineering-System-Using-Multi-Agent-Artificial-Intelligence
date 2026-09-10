"""Tests for Phase 1 modules - chay khong can API key"""
import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

class TestIOCExtractor:
    def setup_method(self):
        from src.extraction.ioc_engine import IOCExtractor
        self.extractor = IOCExtractor()

    def test_extract_mitre_id(self):
        result = self.extractor.extract_from_text("Technique T1059.001 used")
        assert "T1059.001" in result.mitre_ids

    def test_extract_cve(self):
        result = self.extractor.extract_from_text("Exploiting CVE-2021-44228")
        assert "CVE-2021-44228" in result.cves

    def test_refang(self):
        from src.extraction.ioc_engine import refang
        assert refang("hxxp://evil[.]com") == "http://evil.com"
        assert refang("192.168[.]1.1") == "192.168.1.1"

    def test_empty_text(self):
        result = self.extractor.extract_from_text("")
        assert result.total_count == 0

class TestSigmaValidator:
    VALID_RULE = """title: Test Rule
id: 3e3ceccd-1234-4567-89ab-cdef01234567
status: experimental
description: Test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains: '-urlcache'
    condition: selection
falsepositives:
    - Legitimate use
level: high
tags:
    - attack.t1105"""

    def setup_method(self):
        from src.validation.sigma_validator import SigmaValidator
        self.validator = SigmaValidator()

    def test_valid_rule(self):
        result = self.validator.validate(self.VALID_RULE)
        assert result.valid

    def test_empty_rule(self):
        result = self.validator.validate("")
        assert not result.valid

class TestYaraValidator:
    VALID_YARA = """rule Test {
    meta:
        description = "Test rule"
    strings:
        $s1 = "certutil" nocase
        $s2 = "-urlcache" nocase
    condition:
        all of them
}"""
    def setup_method(self):
        from src.validation.yara_validator import YaraValidator
        self.validator = YaraValidator()

    def test_valid_rule(self):
        result = self.validator.validate(self.VALID_YARA)
        assert result.valid

    def test_empty_rule(self):
        result = self.validator.validate("")
        assert not result.valid

class TestSettings:
    def test_settings_load(self):
        from src.config.settings import get_settings
        settings = get_settings()
        assert settings is not None
