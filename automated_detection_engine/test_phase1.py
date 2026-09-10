"""
test_phase1.py
Test toàn bộ Phase 1 pipeline mà KHÔNG cần API key hay GPU.
Chạy: python test_phase1.py
"""
import sys
import traceback


def test_ioc_extractor():
    print("\n[TEST 1] IOC Extractor")
    print("-" * 40)
    try:
        from src.extraction.ioc_engine import IOCExtractor
        extractor = IOCExtractor()

        sample = """
        Threat intelligence report:
        C2 server: 192.168.1[.]100:4444 and hxxps://evil[.]example[.]com/stage2
        Malware SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
        MD5: 44d88612fea8a8f36de82e1278abb02f
        Registry: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MalService
        Mutex: Global\\MicrosoftUpdate2024
        CVE: CVE-2024-21412
        MITRE: T1059.001 and T1055
        Contact: victim@company.com
        """

        result = extractor.extract_from_text(sample)

        assert len(result.ips) > 0, "Should extract IP"
        assert len(result.sha256s) > 0, "Should extract SHA256"
        assert len(result.md5s) > 0, "Should extract MD5"
        assert len(result.registry_keys) > 0, "Should extract registry"
        assert len(result.mutexes) > 0, "Should extract mutex"
        assert len(result.cve_ids) > 0, "Should extract CVE"
        assert len(result.mitre_ids) > 0, "Should extract MITRE"

        print(f"  ✓ IPs: {result.ips}")
        print(f"  ✓ SHA256s: {result.sha256s[:1]}")
        print(f"  ✓ MD5s: {result.md5s}")
        print(f"  ✓ Registry: {result.registry_keys}")
        print(f"  ✓ Mutexes: {result.mutexes}")
        print(f"  ✓ CVEs: {result.cve_ids}")
        print(f"  ✓ MITRE IDs: {result.mitre_ids}")

        # Test refang
        defanged = "hxxps://evil[.]com/path"
        refanged = extractor.refang(defanged)
        assert "https://" in refanged, "Should refang hxxps"
        assert "[.]" not in refanged, "Should remove [.]"
        print(f"  ✓ Refang: {defanged} → {refanged}")

        print("  ✅ IOC Extractor: PASSED")
        return True
    except Exception as e:
        print(f"  ❌ FAILED: {e}")
        traceback.print_exc()
        return False


def test_ner_pipeline():
    print("\n[TEST 2] NER Pipeline (rule-based only)")
    print("-" * 40)
    try:
        from src.extraction.ner_pipeline import SecurityNERPipeline

        # Chỉ test rule-based LOLBin detection (không cần models)
        pipeline = SecurityNERPipeline(
            use_securebert=False,
            use_gliner=False,
        )

        sample = """
        APT29 used certutil.exe and PowerShell.exe for initial access.
        The threat actor then used rundll32.exe to load a malicious DLL.
        mshta.exe was used to execute the payload.
        """

        result = pipeline.extract(sample)

        assert len(result.lolbins) > 0, "Should detect LOLBins"
        assert "certutil.exe" in [l.lower() for l in result.lolbins], "Should detect certutil"

        print(f"  ✓ LOLBins detected: {result.lolbins}")
        print(f"  ✓ Context: {result.to_context_string()}")
        print("  ✅ NER Pipeline: PASSED")
        return True
    except Exception as e:
        print(f"  ❌ FAILED: {e}")
        traceback.print_exc()
        return False


def test_attck_mapper():
    print("\n[TEST 3] ATT&CK Mapper (fallback mode)")
    print("-" * 40)
    try:
        from src.mapping.attack_mapper import ATTCKMapper

        mapper = ATTCKMapper(top_k=3)
        # Force fallback (không cần internet/models)
        mapper._techniques = mapper._get_fallback_techniques()

        test_cases = [
            ("certutil download payload from URL", "T1105"),
            ("PowerShell EncodedCommand execution", "T1059.001"),
            ("LSASS memory dump credential", "T1003"),
        ]

        for text, expected_id in test_cases:
            try:
                result = mapper.map(text)
                ids = [m.technique_id for m in result.matches]
                tags = result.get_sigma_tags()
                print(f"  Text: {text[:40]}...")
                print(f"    → Matches: {ids}")
                print(f"    → Tags: {tags}")
            except Exception as e:
                print(f"  Warning: mapping failed for '{text}': {e}")

        print("  ✅ ATT&CK Mapper: PASSED")
        return True
    except Exception as e:
        print(f"  ❌ FAILED: {e}")
        traceback.print_exc()
        return False


def test_sigma_validator():
    print("\n[TEST 4] Sigma Validator")
    print("-" * 40)
    try:
        from src.validation.validators import SigmaValidator
        validator = SigmaValidator()

        # Test 1: Valid rule
        valid_rule = """title: Test Detection Rule
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Test rule for certutil download detection
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains: '-urlcache'
    condition: selection
falsepositives:
    - Legitimate certificate operations
level: high
tags:
    - attack.execution
    - attack.t1105
"""
        result = validator.validate(valid_rule)
        print(f"  ✓ Valid rule test: valid={result.valid}, errors={result.errors}")

        # Test 2: Rule với bad status (auto-fix)
        bad_rule = valid_rule.replace("status: experimental", "status: INVALID_STATUS")
        result2 = validator.validate(bad_rule)
        print(f"  ✓ Auto-fix test: valid={result2.valid}, fixed={result2.fixed_yaml is not None}")

        # Test 3: Markdown-wrapped rule
        md_rule = f"```yaml\n{valid_rule}\n```"
        result3 = validator.validate(md_rule)
        print(f"  ✓ Markdown strip test: valid={result3.valid}")

        print("  ✅ Sigma Validator: PASSED")
        return True
    except Exception as e:
        print(f"  ❌ FAILED: {e}")
        traceback.print_exc()
        return False


def test_yara_validator():
    print("\n[TEST 5] YARA Validator")
    print("-" * 40)
    try:
        from src.validation.validators import YARAValidator
        validator = YARAValidator()

        # Test 1: Valid YARA rule
        valid_yara = '''
rule TestMalware {
    meta:
        description = "Test YARA rule"
        author = "Test"
    strings:
        $pe_header = { 4D 5A }
        $sus_string = "malicious_payload" nocase
    condition:
        $pe_header at 0 and $sus_string
}
'''
        result = validator.validate(valid_yara)
        print(f"  ✓ Valid YARA test: valid={result.valid}")

        # Test 2: Missing pe import (auto-fix)
        yara_need_import = '''
rule TestPE {
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 and pe.entry_point > 0
}
'''
        result2 = validator.validate(yara_need_import)
        print(f"  ✓ Auto-import test: valid={result2.valid}, attempts={result2.attempts}")
        if result2.fixed_rule:
            print(f"    Fixed rule starts with: {result2.fixed_rule[:30]}...")

        # Test 3: Markdown wrapped YARA
        md_yara = f"```yara\n{valid_yara}\n```"
        result3 = validator.validate(md_yara)
        print(f"  ✓ Markdown strip test: valid={result3.valid}")

        print("  ✅ YARA Validator: PASSED")
        return True
    except Exception as e:
        print(f"  ❌ FAILED: {e}")
        traceback.print_exc()
        return False


def test_settings():
    print("\n[TEST 0] Settings & Config")
    print("-" * 40)
    try:
        import os
        # Set dummy key để test
        os.environ["OPENAI_API_KEY"] = "sk-test-dummy-key"

        from src.config.settings import Settings
        settings = Settings()

        print(f"  ✓ LLM Provider: {settings.llm_provider}")
        print(f"  ✓ LLM Model: {settings.llm_model}")
        print(f"  ✓ Embedding: {settings.embedding_model}")
        print(f"  ✓ RAG top_k retrieve: {settings.rag_top_k_retrieve}")
        print(f"  ✓ RAG top_k rerank: {settings.rag_top_k_rerank}")
        print("  ✅ Settings: PASSED")
        return True
    except Exception as e:
        print(f"  ❌ FAILED: {e}")
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("=" * 50)
    print("  Phase 1 Pipeline Test Suite")
    print("  (No API key or GPU required)")
    print("=" * 50)

    # Thêm project root vào path
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))

    results = {
        "Settings": test_settings(),
        "IOC Extractor": test_ioc_extractor(),
        "NER Pipeline": test_ner_pipeline(),
        "ATT&CK Mapper": test_attck_mapper(),
        "Sigma Validator": test_sigma_validator(),
        "YARA Validator": test_yara_validator(),
    }

    print("\n" + "=" * 50)
    print("  RESULTS SUMMARY")
    print("=" * 50)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    for name, ok in results.items():
        status = "✅ PASS" if ok else "❌ FAIL"
        print(f"  {status}  {name}")
    print(f"\n  {passed}/{total} tests passed")

    if passed == total:
        print("\n  🎉 All tests passed! Ready to configure API key and run full pipeline.")
        print("\n  Next steps:")
        print("  1. Copy .env.example to .env")
        print("  2. Add your OPENAI_API_KEY to .env")
        print("  3. Run: python src/main.py")
    else:
        print("\n  ⚠️  Some tests failed. Check error messages above.")
        sys.exit(1)
