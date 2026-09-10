"""
extraction/ner_pipeline.py
NER Pipeline kết hợp SecureBERT 2.0 (specialized) + GLiNER (zero-shot).
SecureBERT 2.0: nhận diện entities cố định (Malware, Threat Actor, CVE...)
GLiNER: zero-shot cho emerging threats chưa có label
"""
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class SecurityEntity:
    text: str
    label: str          # MALWARE | THREAT_ACTOR | CVE | CAMPAIGN | TOOL | LOLBIN | ...
    start: int
    end: int
    confidence: float
    source: str         # "securebert" | "gliner"


@dataclass
class NERResult:
    entities: list[SecurityEntity] = field(default_factory=list)
    malware_names: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    campaigns: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    lolbins: list[str] = field(default_factory=list)

    def to_context_string(self) -> str:
        """Tóm tắt cho LLM context."""
        parts = []
        if self.malware_names:
            parts.append(f"Malware: {', '.join(self.malware_names)}")
        if self.threat_actors:
            parts.append(f"Threat Actors: {', '.join(self.threat_actors)}")
        if self.campaigns:
            parts.append(f"Campaigns: {', '.join(self.campaigns)}")
        if self.tools:
            parts.append(f"Tools: {', '.join(self.tools)}")
        if self.lolbins:
            parts.append(f"LOLBins: {', '.join(self.lolbins)}")
        return " | ".join(parts) if parts else "No specific entities identified"


# LOLBins list cố định - Living Off the Land Binaries
LOLBINS = {
    "certutil.exe", "mshta.exe", "regsvr32.exe", "wscript.exe",
    "cscript.exe", "rundll32.exe", "msiexec.exe", "powershell.exe",
    "cmd.exe", "wmic.exe", "bitsadmin.exe", "forfiles.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "cmstp.exe", "control.exe", "odbcconf.exe", "pcalua.exe",
    "presentationhost.exe", "replace.exe", "rpcping.exe",
    "sfc.exe", "syncappvpublishingserver.exe", "appsyncpublishingserver.exe",
    "expand.exe", "extrac32.exe", "findstr.exe", "ieexec.exe",
    "makecab.exe", "mavinject.exe", "microsoft.workflow.compiler.exe",
    "msdeploy.exe", "msdt.exe", "msiexec.exe", "mspub.exe",
    "msconfig.exe", "netsh.exe", "ntdsutil.exe", "pcwrun.exe",
}


class SecurityNERPipeline:
    """
    Hybrid NER pipeline:
    1. SecureBERT 2.0 cho cybersecurity-specific entities
    2. GLiNER cho zero-shot extraction của emerging threats
    3. Rule-based cho LOLBins
    """

    def __init__(
        self,
        use_securebert: bool = True,
        use_gliner: bool = True,
        device: str = "cpu",           # "cpu" | "cuda" | "mps"
        confidence_threshold: float = 0.7,
    ):
        self.use_securebert = use_securebert
        self.use_gliner = use_gliner
        self.device = device
        self.confidence_threshold = confidence_threshold
        self._securebert = None
        self._gliner = None

    def _load_securebert(self):
        """Lazy load SecureBERT 2.0 NER model."""
        if self._securebert is not None:
            return
        try:
            from transformers import pipeline
            logger.info("Loading SecureBERT 2.0 NER model...")
            self._securebert = pipeline(
                "token-classification",
                model="cisco-ai/SecureBERT2.0-NER",
                aggregation_strategy="simple",
                device=0 if self.device == "cuda" else -1,
            )
            logger.info("SecureBERT 2.0 loaded successfully")
        except Exception as e:
            logger.warning(f"SecureBERT load failed: {e}. Falling back to rule-based only.")
            self.use_securebert = False

    def _load_gliner(self):
        """Lazy load GLiNER model."""
        if self._gliner is not None:
            return
        try:
            from gliner import GLiNER
            logger.info("Loading GLiNER model...")
            self._gliner = GLiNER.from_pretrained("urchade/gliner_medium-v2.1")
            logger.info("GLiNER loaded successfully")
        except Exception as e:
            logger.warning(f"GLiNER load failed: {e}.")
            self.use_gliner = False

    def _extract_securebert(self, text: str) -> list[SecurityEntity]:
        """Extract entities với SecureBERT 2.0."""
        self._load_securebert()
        if not self._securebert:
            return []

        try:
            raw_entities = self._securebert(text)
            entities = []
            for ent in raw_entities:
                if ent["score"] >= self.confidence_threshold:
                    entities.append(SecurityEntity(
                        text=ent["word"],
                        label=ent["entity_group"],
                        start=ent["start"],
                        end=ent["end"],
                        confidence=ent["score"],
                        source="securebert",
                    ))
            return entities
        except Exception as e:
            logger.error(f"SecureBERT inference error: {e}")
            return []

    def _chunk_text(self,text,chunk_size=4000,overlap=300):
        chunks=[];i=0;n=len(text)
        while i<n:
            e=min(n,i+chunk_size);chunks.append((i,text[i:e]));i=max(e-overlap,e if e==n else e-overlap)
            if e==n: break
        return chunks

    def _extract_gliner(self, text: str) -> list[SecurityEntity]:
        """Zero-shot extraction với GLiNER cho emerging threats."""
        self._load_gliner()
        if not self._gliner:
            return []

        # Labels cho zero-shot extraction
        gliner_labels = [
            "malware family",
            "threat actor group",
            "attack campaign",
            "hacking tool",
            "vulnerability",
            "targeted organization",
            "command and control server",
        ]

        try:
            entities = []
            for offset,chunk in self._chunk_text(text):
                raw_entities=self._gliner.predict_entities(chunk,gliner_labels,threshold=self.confidence_threshold)
                for ent in raw_entities:
                    ent["start"]+=offset; ent["end"]+=offset
                    label_map = {
            for ent in raw_entities:
                # Map GLiNER labels sang standard labels
                label_map = {
                    "malware family": "MALWARE",
                    "threat actor group": "THREAT_ACTOR",
                    "attack campaign": "CAMPAIGN",
                    "hacking tool": "TOOL",
                    "vulnerability": "VULNERABILITY",
                    "targeted organization": "TARGET",
                    "command and control server": "C2",
                }
                std_label = label_map.get(ent["label"], ent["label"].upper())
                entities.append(SecurityEntity(
                    text=ent["text"],
                    label=std_label,
                    start=ent["start"],
                    end=ent["end"],
                    confidence=ent["score"],
                    source="gliner",
                ))
            return entities
        except Exception as e:
            logger.error(f"GLiNER inference error: {e}")
            return []

    def _extract_lolbins(self, text: str) -> list[SecurityEntity]:
        """Rule-based LOLBin detection."""
        import re
        entities = []
        for lolbin in LOLBINS:
            pattern = re.compile(re.escape(lolbin), re.IGNORECASE)
            for match in pattern.finditer(text):
                entities.append(SecurityEntity(
                    text=match.group(),
                    label="LOLBIN",
                    start=match.start(),
                    end=match.end(),
                    confidence=1.0,
                    source="rule_based",
                ))
        return entities

    def _merge_and_deduplicate(
        self,
        *entity_lists: list[SecurityEntity],
    ) -> list[SecurityEntity]:
        """
        Merge entities từ nhiều sources, deduplicate theo text + label.
        SecureBERT ưu tiên hơn GLiNER nếu overlap.
        """
        seen = {}
        for entities in entity_lists:
            for ent in entities:
                key = (ent.text.lower(), ent.label)
                if key not in seen or ent.source == "securebert":
                    seen[key] = ent
        return list(seen.values())

    def extract(self, text: str) -> NERResult:
        """Main extraction method - chạy toàn bộ pipeline."""
        result = NERResult()

        # 1. SecureBERT extraction
        sb_entities = self._extract_securebert(text) if self.use_securebert else []

        # 2. GLiNER zero-shot
        gl_entities = self._extract_gliner(text) if self.use_gliner else []

        # 3. Rule-based LOLBins
        lb_entities = self._extract_lolbins(text)

        # 4. Merge + deduplicate
        all_entities = self._merge_and_deduplicate(sb_entities, gl_entities, lb_entities)
        result.entities = all_entities

        # 5. Organize by category
        for ent in all_entities:
            if ent.label == "MALWARE":
                result.malware_names.append(ent.text)
            elif ent.label == "THREAT_ACTOR":
                result.threat_actors.append(ent.text)
            elif ent.label == "CAMPAIGN":
                result.campaigns.append(ent.text)
            elif ent.label in ("TOOL", "SOFTWARE"):
                result.tools.append(ent.text)
            elif ent.label == "LOLBIN":
                result.lolbins.append(ent.text)

        # Deduplicate lists
        result.malware_names = list(dict.fromkeys(result.malware_names))
        result.threat_actors = list(dict.fromkeys(result.threat_actors))
        result.campaigns = list(dict.fromkeys(result.campaigns))
        result.tools = list(dict.fromkeys(result.tools))
        result.lolbins = list(dict.fromkeys(result.lolbins))

        logger.info(
            f"NER: {len(result.malware_names)} malware, "
            f"{len(result.threat_actors)} actors, "
            f"{len(result.lolbins)} LOLBins"
        )
        return result


# ── Quick test ───────────────────────────────────────────────
if __name__ == "__main__":
    # Test rule-based sẽ luôn chạy được, không cần models
    pipeline = SecurityNERPipeline(
        use_securebert=False,   # Tắt để test nhanh
        use_gliner=False,
    )

    sample = """
    APT29 (Cozy Bear) used Cobalt Strike and certutil.exe to download
    the NOBELIUM backdoor. PowerShell.exe was used for lateral movement.
    The campaign targeted Microsoft Exchange servers.
    """

    result = pipeline.extract(sample)
    print("=== NER Result ===")
    print(f"LOLBins detected: {result.lolbins}")
    print(f"Context: {result.to_context_string()}")
