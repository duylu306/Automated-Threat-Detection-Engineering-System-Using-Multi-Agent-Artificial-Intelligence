"""
src/extraction/attck_mapper.py
──────────────────────────────
Map text mo ta tan cong → MITRE ATT&CK techniques.
Dung sentence-transformers + cosine similarity (zero-shot).
"""
import json
import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class TechniqueMatch:
    technique_id: str        # T1059.001
    technique_name: str      # PowerShell
    tactic: str              # Execution
    confidence: float        # 0.0 - 1.0
    description: str = ""

    def to_dict(self) -> dict:
        return self.__dict__


class ATTCKMapper:
    """
    Zero-shot ATT&CK technique mapper dung sentence-transformers.

    Usage:
        mapper = ATTCKMapper()
        results = mapper.map("PowerShell ran encoded command connecting to C2")
        for r in results:
            print(r.technique_id, r.confidence)
    """

    def __init__(
        self,
        embedding_model: str = "BAAI/bge-small-en-v1.5",
        top_k: int = 5,
        confidence_threshold: float = 0.3,
    ):
        self.embedding_model_name = embedding_model
        self.top_k = top_k
        self.confidence_threshold = confidence_threshold
        self._model = None
        self._technique_embeddings = None
        self._techniques: list[dict] = []

    def _load_model(self):
        """Lazy load model chi khi can."""
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            logger.info(f"Loading embedding model: {self.embedding_model_name}")
            self._model = SentenceTransformer(self.embedding_model_name)

    def _load_attck_data(self) -> list[dict]:
        """
        Load ATT&CK data tu mitreattack-python.
        Fallback: download STIX bundle tu GitHub.
        """
        try:
            from mitreattack.stix20 import MitreAttackData
            # Enterprise ATT&CK
            mitre_data = MitreAttackData(
                "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                "master/enterprise-attack/enterprise-attack.json"
            )
            techniques = []
            for t in mitre_data.get_techniques(remove_revoked_deprecated=True):
                ext_refs = t.get("external_references", [])
                attck_ref = next(
                    (r for r in ext_refs if r.get("source_name") == "mitre-attack"),
                    None
                )
                if not attck_ref:
                    continue

                technique_id = attck_ref.get("external_id", "")
                if not technique_id.startswith("T"):
                    continue

                # Lay tactic name
                kill_chain = t.get("kill_chain_phases", [])
                tactic = kill_chain[0].get("phase_name", "").replace("-", " ").title() \
                    if kill_chain else "Unknown"

                techniques.append({
                    "id": technique_id,
                    "name": t.get("name", ""),
                    "description": t.get("description", "")[:500],  # truncate
                    "tactic": tactic,
                    # Text dung de embed: name + description
                    "embed_text": f"{t.get('name', '')}. {t.get('description', '')[:300]}"
                })

            logger.info(f"Loaded {len(techniques)} ATT&CK techniques")
            return techniques

        except Exception as e:
            logger.error(f"Failed to load ATT&CK data: {e}")
            # Fallback: mot so technique pho bien nhat
            return self._get_fallback_techniques()

    def _get_fallback_techniques(self) -> list[dict]:
        """Fallback khi khong load duoc ATT&CK data."""
        return [
            {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution",
             "description": "Adversaries may abuse PowerShell commands and scripts.",
             "embed_text": "PowerShell command execution scripting interpreter"},
            {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion",
             "description": "Adversaries may inject code into processes.",
             "embed_text": "process injection shellcode memory dll"},
            {"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access",
             "description": "Adversaries may attempt to access credential material in LSASS.",
             "embed_text": "credential dumping lsass memory procdump mimikatz"},
            {"id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence",
             "description": "Adversaries may achieve persistence by adding registry run keys.",
             "embed_text": "registry run key autostart persistence boot logon"},
            {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control",
             "description": "Adversaries may communicate using HTTP/HTTPS protocols.",
             "embed_text": "C2 command control HTTP HTTPS web protocol beacon"},
            {"id": "T1070.001", "name": "Clear Windows Event Logs", "tactic": "Defense Evasion",
             "description": "Adversaries may clear Windows Event Logs to hide activity.",
             "embed_text": "clear event log wevtutil indicator removal cover tracks"},
            {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control",
             "description": "Adversaries may transfer tools from external systems.",
             "embed_text": "download file certutil bitsadmin wget curl payload delivery"},
            {"id": "T1562.001", "name": "Disable or Modify Tools", "tactic": "Defense Evasion",
             "description": "Adversaries may disable security tools.",
             "embed_text": "disable antivirus security tool tamper defender"},
        ]

    def _build_index(self):
        """Build embedding index cho tat ca techniques."""
        if self._technique_embeddings is not None:
            return

        self._load_model()
        self._techniques = self._load_attck_data()

        embed_texts = [t["embed_text"] for t in self._techniques]
        logger.info(f"Building embeddings for {len(embed_texts)} techniques...")
        self._technique_embeddings = self._model.encode(
            embed_texts,
            normalize_embeddings=True,
            show_progress_bar=True,
            batch_size=32,
        )
        logger.info("ATT&CK index built successfully")

    def map(
        self,
        text: str,
        top_k: Optional[int] = None,
    ) -> list[TechniqueMatch]:
        """
        Map mot doan text → list TechniqueMatch theo confidence giam dan.

        Args:
            text: Mo ta tan cong / log entry / CTI excerpt
            top_k: So ket qua tra ve (default: self.top_k)

        Returns:
            list[TechniqueMatch] sap xep theo confidence giam dan
        """
        if not text or not text.strip():
            return []

        self._build_index()
        k = top_k or self.top_k

        # Encode query
        query_embedding = self._model.encode(
            text,
            normalize_embeddings=True,
        )

        # Cosine similarity (embeddings da normalize → dot product = cosine)
        scores = np.dot(self._technique_embeddings, query_embedding)

        # Top-k indices
        top_indices = np.argsort(scores)[::-1][:k]

        results = []
        for idx in top_indices:
            confidence = float(scores[idx])
            if confidence < self.confidence_threshold:
                break
            t = self._techniques[idx]
            results.append(TechniqueMatch(
                technique_id=t["id"],
                technique_name=t["name"],
                tactic=t["tactic"],
                confidence=round(confidence, 4),
                description=t["description"],
            ))

        return results

    def map_with_mitre_ids(
        self,
        text: str,
        existing_ids: list[str],
    ) -> list[TechniqueMatch]:
        """
        Ket hop: extract MITRE IDs truc tiep tu text +
        semantic similarity cho phan con lai.
        """
        import re
        found_ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)
        all_ids = list(set(existing_ids + found_ids))

        # Tim techniques tuong ung voi IDs tim duoc
        direct_matches = []
        self._build_index()
        for tech_id in all_ids:
            matched = next(
                (t for t in self._techniques if t["id"] == tech_id), None
            )
            if matched:
                direct_matches.append(TechniqueMatch(
                    technique_id=matched["id"],
                    technique_name=matched["name"],
                    tactic=matched["tactic"],
                    confidence=1.0,   # direct match
                    description=matched["description"],
                ))

        # Semantic matches cho text
        semantic = self.map(text, top_k=self.top_k)

        # Merge: direct matches truoc, sau do semantic (bo trung)
        seen_ids = {m.technique_id for m in direct_matches}
        for s in semantic:
            if s.technique_id not in seen_ids:
                direct_matches.append(s)
                seen_ids.add(s.technique_id)

        return direct_matches[:self.top_k]


# Type hint fix
from typing import Optional
