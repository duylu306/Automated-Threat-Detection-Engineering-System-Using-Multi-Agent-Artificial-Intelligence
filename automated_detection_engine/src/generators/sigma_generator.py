"""
src/generators/sigma_generator.py
───────────────────────────────────
Sinh Sigma rules dung LLM + RAG.
Support: OpenAI, Anthropic, Ollama.
"""
import logging
from dataclasses import dataclass, field
from typing import Optional

import yaml

from src.config.settings import get_settings, LLMProvider

logger = logging.getLogger(__name__)


# ─── Prompt Templates ─────────────────────────────────────────────────────────

SIGMA_SYSTEM_PROMPT = """
You are a strict, factual Detection Engineer specializing in Sigma rules.
Your task is to convert threat intelligence into valid Sigma rules.

STRICT REQUIREMENTS:
1. Output ONLY raw YAML - no markdown, no code blocks, no text explanations outside of YAML comments.
2. Include ALL required fields:
   title, id (UUID), status, description, logsource,
   detection, condition, falsepositives, level, tags.
3. Status must be: experimental.
4. Level must be one of:
   informational, low, medium, high, critical.
5. Use exact field names when applicable:
   CommandLine, Image, ParentImage, TargetImage, TargetFilename, DestinationIp, DestinationHostname.
6. Tags must follow Sigma format:
   attack.tXXXX or attack.<tactic_name>.
7. Arrays/Lists: Use proper YAML list indentation (e.g., - 'value').

SCOPE ISOLATION:
- Focus strictly on the ATT&CK technique provided in the context.
- If the technique is behavior-based, generate detections only for that behavior.
- Do not inject unrelated network IOCs into behavior-based rules.

ANTI-HALLUCINATION (CRITICAL):
- Build rules ONLY from entities, IOCs, and behaviors explicitly described in the THREAT INTELLIGENCE section.
- Do NOT invent tools, malware families, commands, registry paths, or behaviors.
- Do NOT assume credential dumping, lateral movement, persistence mechanisms, or specific tools (e.g., Mimikatz, Cobalt Strike) unless explicitly stated.

RAG RULES ARE TEMPLATES ONLY:
- The SIMILAR EXISTING RULES section is provided strictly for YAML syntax, field usage, and logsource reference.
- NEVER copy detection logic, IOCs, tools, filenames, commands, or indicators from the examples.

REASONING PROCESS (MUST BE IN YAML COMMENTS):
Before writing the actual rule fields, output your reasoning process as YAML comments (starting with #).
# Step 1: Extract only explicitly stated facts, tools, and IOCs.
# Step 2: Ignore all indicators appearing only in RAG examples.
# Step 3: Identify the ATT&CK technique and tactic.
# Step 4: Determine the most appropriate log source.
# Step 5: Select fields that uniquely identify the described behavior.
# Step 6: Write detection logic using appropriate modifiers.
# Step 7: Add metadata and realistic false positives.
"""

SIGMA_FEW_SHOT_EXAMPLES = [
    {
        "input": "Certutil.exe used to download files from external URL using -urlcache flag",
        "output": """title: Certutil Download From URL
id: 3e3ceccd-1234-4567-89ab-cdef01234567
status: experimental
description: Detects certutil.exe downloading files from external URLs, a common LOLBIN abuse technique
author: AI Detection Engine
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains|all:
            - '-urlcache'
            - 'http'
    condition: selection
falsepositives:
    - Legitimate certificate downloads by administrators
level: high
tags:
    - attack.t1105
    - attack.command_and_control"""
    },
    {
        "input": "PowerShell running encoded commands with suspicious base64 content",
        "output": """title: PowerShell Encoded Command Execution
id: 4f4dedde-2345-5678-90bc-def012345678
status: experimental
description: Detects PowerShell executing base64 encoded commands which is commonly used to obfuscate malicious payloads
author: AI Detection Engine
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains:
            - ' -EncodedCommand '
            - ' -enc '
            - ' -e '
    condition: selection
falsepositives:
    - Legitimate administrative scripts using encoded commands
    - Software installation scripts
level: medium
tags:
    - attack.t1059.001
    - attack.execution"""
    }
]


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class GenerationContext:
    """Context duoc truyen vao generator."""
    input_text: str
    input_type: str = "text"          # text | log | ioc_list | pdf_excerpt
    attck_techniques: list[str] = field(default_factory=list)
    logsource_hint: str = ""          # goi y logsource
    ioc_data: dict = field(default_factory=dict)
    retrieved_rules: list[str] = field(default_factory=list)   # tu RAG


@dataclass
class SigmaResult:
    """Ket qua tu Sigma generator."""
    rule_yaml: str = ""
    technique_ids: list[str] = field(default_factory=list)
    confidence: float = 0.0
    explanation: str = ""
    attempts: int = 0
    valid: bool = False
    quality_score: int = 0


# ─── Generator ────────────────────────────────────────────────────────────────

class SigmaGenerator:
    """
    Sinh Sigma rules tu attack descriptions.

    Usage:
        generator = SigmaGenerator()
        ctx = GenerationContext(
            input_text="Attacker used certutil to download payload",
            attck_techniques=["T1105"],
        )
        result = await generator.generate(ctx)
        print(result.rule_yaml)
    """

    def __init__(self):
        self.settings = get_settings()
        self._llm = None

    def _get_llm(self):
        """Lazy init LLM client."""
        if self._llm is not None:
            return self._llm

        provider = self.settings.llm_provider

        if provider == LLMProvider.OPENAI:
            from langchain_openai import ChatOpenAI
            self._llm = ChatOpenAI(
                model=self.settings.llm_model,
                temperature=self.settings.llm_temperature,
                max_tokens=self.settings.llm_max_tokens,
                api_key=self.settings.openai_api_key,
            )

        elif provider == LLMProvider.ANTHROPIC:
            from langchain_anthropic import ChatAnthropic
            self._llm = ChatAnthropic(
                model=self.settings.llm_model,
                temperature=self.settings.llm_temperature,
                max_tokens=self.settings.llm_max_tokens,
                api_key=self.settings.anthropic_api_key,
            )

        elif provider == LLMProvider.OLLAMA:
            from langchain_community.chat_models import ChatOllama
            self._llm = ChatOllama(
                model=self.settings.ollama_model,
                temperature=self.settings.llm_temperature,
                base_url=self.settings.ollama_base_url,
            )
        elif provider == LLMProvider.GOOGLE:
            from langchain_google_genai import ChatGoogleGenerativeAI
            self._llm = ChatGoogleGenerativeAI(
                model=self.settings.llm_model,
                temperature=self.settings.llm_temperature,
                max_tokens=self.settings.llm_max_tokens,
                google_api_key=self.settings.google_api_key,
            )

        return self._llm

    def _build_prompt(self, ctx: GenerationContext) -> str:
        """Xay dung user prompt tu context."""
        parts = []

        # Few-shot examples
        parts.append("=== REFERENCE EXAMPLES ===")
        for ex in SIGMA_FEW_SHOT_EXAMPLES[:2]:
            parts.append(f"INPUT: {ex['input']}")
            parts.append(f"OUTPUT:\n{ex['output']}")
            parts.append("---")

        # RAG context
        if ctx.retrieved_rules:
            parts.append("\n=== SIMILAR EXISTING RULES (for reference) ===")
            for i, rule in enumerate(ctx.retrieved_rules[:3]):
                parts.append(f"[Rule {i+1}]\n{rule[:500]}...")
            parts.append("")

        # ATT&CK hints
        if ctx.attck_techniques:
            parts.append(f"ATT&CK Techniques identified: {', '.join(ctx.attck_techniques)}")

        if ctx.logsource_hint:
            parts.append(f"Suggested log source: {ctx.logsource_hint}")

        # IOC data
        if ctx.ioc_data:
            ioc_summary = []
            for ioc_type, values in ctx.ioc_data.items():
                if values and isinstance(values, list):
                    ioc_summary.append(f"{ioc_type}: {', '.join(str(v) for v in values[:5])}")
            if ioc_summary:
                parts.append(f"Extracted IOCs: {'; '.join(ioc_summary)}")

        # Main input
        parts.append(f"\n=== THREAT INTELLIGENCE / ATTACK DESCRIPTION ===")
        parts.append(ctx.input_text)
        parts.append("\n=== GENERATE SIGMA RULE (YAML only, no markdown) ===")

        return "\n".join(parts)

    async def generate(self, ctx: GenerationContext) -> SigmaResult:
        """Sinh Sigma rule voi retry loop."""
        from src.validation.sigma_validator import SigmaValidator

        validator = SigmaValidator()
        llm = self._get_llm()

        from langchain_core.messages import SystemMessage, HumanMessage

        max_attempts = self.settings.max_validation_retries
        last_error = ""

        for attempt in range(1, max_attempts + 1):
            try:
                # Build messages
                user_content = self._build_prompt(ctx)
                if last_error and attempt > 1:
                    user_content += f"\n\n=== PREVIOUS ATTEMPT HAD ERRORS ===\n{last_error}\nPlease fix these issues."

                messages = [
                    SystemMessage(content=SIGMA_SYSTEM_PROMPT),
                    HumanMessage(content=user_content),
                ]

                logger.info(f"Sigma generation attempt {attempt}/{max_attempts}")
                response = await llm.ainvoke(messages)
                raw_output = response.content.strip()

                # Clean markdown backticks neu co
                raw_output = raw_output.replace("```yaml", "").replace("```", "").strip()

                # Validate
                validation = validator.validate(raw_output)

                if validation.valid:
                    logger.info(f"Valid Sigma rule generated (attempt {attempt}, score {validation.score})")
                    return SigmaResult(
                        rule_yaml=validation.fixed_yaml or raw_output,
                        technique_ids=ctx.attck_techniques,
                        confidence=validation.score / 10.0,
                        attempts=attempt,
                        valid=True,
                        quality_score=validation.score,
                    )
                else:
                    # Compile error messages cho lan sau
                    errors = [i.message for i in validation.issues if i.severity == "error"]
                    last_error = "\n".join(errors)
                    logger.warning(f"Attempt {attempt} failed: {last_error}")

                    # Neu da fix duoc thi dung luon
                    if validation.fixed_yaml and validation.fixed_yaml != raw_output:
                        re_validate = validator.validate(validation.fixed_yaml)
                        if re_validate.valid:
                            return SigmaResult(
                                rule_yaml=validation.fixed_yaml,
                                technique_ids=ctx.attck_techniques,
                                confidence=re_validate.score / 10.0,
                                attempts=attempt,
                                valid=True,
                                quality_score=re_validate.score,
                            )

            except Exception as e:
                logger.error(f"LLM call failed (attempt {attempt}): {e}")
                last_error = str(e)

        # Tra ve invalid result sau khi het retries
        return SigmaResult(
            rule_yaml="",
            attempts=max_attempts,
            valid=False,
            explanation=f"Failed after {max_attempts} attempts. Last error: {last_error}",
        )

    def generate_sync(self, ctx: GenerationContext) -> SigmaResult:
        """Sync wrapper cho testing."""
        import asyncio
        return asyncio.run(self.generate(ctx))
