"""
mapping/attack_mapper.py
Ánh xạ text mô tả tấn công → MITRE ATT&CK Techniques.
Dùng sentence-transformers cosine similarity (zero-shot) + NER Boost.
"""
import json
import logging
import requests
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import numpy as np

logger = logging.getLogger(__name__)

ATTCK_CACHE_PATH = Path("data/attck_techniques_cache.json")

# TỪ ĐIỂN MAPPING TĨNH TỪ NER SANG MITRE ATT&CK
KNOWN_LOLBIN_MAPPING = {
    "powershell.exe": "T1059.001",
    "powershell": "T1059.001",
    "pwsh.exe": "T1059.001",
    "certutil.exe": "T1105",
    "certutil": "T1105",
    "wmic.exe": "T1047",
    "mshta.exe": "T1218.005",
    "regsvr32.exe": "T1218.010",
    "rundll32.exe": "T1218.011",
    "cmd.exe": "T1059.003",
    "schtasks.exe": "T1053.005",
    "qilin": "T1486",           # Data Encrypted for Impact
    "ivanti": "T1190",          # Exploit Public-Facing Application
    "vpn": "T1133",             # External Remote Services
    "cleo": "T1190",
    "akira": "T1486",
    "clickfix": "T1204.002",
}

@dataclass
class TechniqueMatch:
    technique_id: str       # T1059.001
    technique_name: str     # PowerShell
    tactic: str             # Execution
    confidence: float       # 0.0 - 1.0
    description: str = ""

@dataclass
class ATTCKMapperResult:
    matches: list[TechniqueMatch] = field(default_factory=list)
    primary: Optional[TechniqueMatch] = None

    def get_sigma_tags(self) -> list[str]:
        """Convert matches → Sigma tags format."""
        tags = []
        for m in self.matches:
            # Tactic tag
            tactic_tag = f"attack.{m.tactic.lower().replace(' ', '_')}"
            if tactic_tag not in tags:
                tags.append(tactic_tag)
            # Technique tag
            tech_tag = f"attack.{m.technique_id.lower().replace('.', '_')}"
            tags.append(tech_tag)
        return tags

    def to_dict(self) -> dict:
        return {
            "primary": {
                "id": self.primary.technique_id,
                "name": self.primary.technique_name,
                "tactic": self.primary.tactic,
                "confidence": self.primary.confidence,
            } if self.primary else None,
            "all_matches": [
                {
                    "id": m.technique_id,
                    "name": m.technique_name,
                    "tactic": m.tactic,
                    "confidence": m.confidence,
                }
                for m in self.matches
            ],
            "sigma_tags": self.get_sigma_tags(),
        }


class ATTCKMapper:
    """
    Maps attack descriptions to ATT&CK techniques using:
    1. Sentence-transformers cosine similarity (primary)
    2. Direct MITRE ID lookup (fallback)
    3. NER Entity Boost (LOLBins -> Technique)
    """

    def __init__(
        self,
        embedding_model: str = "BAAI/bge-small-en-v1.5",
        top_k: int = 5,
        confidence_threshold: float = 0.35,
    ):
        self.embedding_model_name = embedding_model
        self.top_k = top_k
        self.confidence_threshold = confidence_threshold
        self._model = None
        self._techniques: list[dict] = []
        self._technique_embeddings: Optional[np.ndarray] = None
        self._software_mapping: dict = {}

    def _load_model(self):
        """Lazy load embedding model."""
        if self._model is not None:
            return
        try:
            from sentence_transformers import SentenceTransformer
            logger.info(f"Loading embedding model: {self.embedding_model_name}")
            self._model = SentenceTransformer(self.embedding_model_name)
            logger.info("Embedding model loaded")
        except ImportError:
            raise ImportError("sentence-transformers chưa được cài")

    def _load_attck_data(self):
        """Load ATT&CK techniques và Software mappings từ cache hoặc download."""
        if self._techniques and self._software_mapping:
            return

        # 1. Thử load từ cache trước
        if ATTCK_CACHE_PATH.exists():
            logger.info("Loading ATT&CK data and Software Mappings from cache...")
            with open(ATTCK_CACHE_PATH) as f:
                cache_data = json.load(f)
                
            # Đọc format mới chứa cả techniques và software mapping
            if isinstance(cache_data, dict) and "techniques" in cache_data:
                self._techniques = cache_data["techniques"]
                self._software_mapping = cache_data.get("software_mapping", {})
                logger.info(f"Loaded {len(self._techniques)} techniques and {len(self._software_mapping)} software mappings from cache")
                return

        # 2. Download từ mitreattack-python nếu chưa có cache
        logger.info("Downloading ATT&CK data from MITRE...")
        try:
            from mitreattack.stix20 import MitreAttackData
            stix_path = "data/enterprise-attack.json"
            
            if not Path(stix_path).exists():
                logger.info("Downloading STIX JSON file to local (khoảng 40MB)...")
                import requests
                url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
                resp = requests.get(url, timeout=60)
                resp.raise_for_status()
                Path(stix_path).parent.mkdir(parents=True, exist_ok=True)
                with open(stix_path, "wb") as f:
                    f.write(resp.content)
            
            mitre_data = MitreAttackData(stix_path)
            
            # --- A. TRÍCH XUẤT KỸ THUẬT (TECHNIQUES) ---
            techniques = mitre_data.get_techniques(remove_revoked_deprecated=True)
            self._techniques = []
            for tech in techniques:
                tech_dict = tech.serialize()
                tech_obj = json.loads(tech_dict)

                tactics = [
                    phase["phase_name"].replace("-", " ").title()
                    for phase in tech_obj.get("kill_chain_phases", [])
                    if phase["kill_chain_name"] == "mitre-attack"
                ]

                attck_id = next((ref.get("external_id", "") for ref in tech_obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"), "")
                if not attck_id: continue

                self._techniques.append({
                    "id": attck_id,
                    "name": tech_obj.get("name", ""),
                    "description": tech_obj.get("description", "")[:500],
                    "tactics": tactics,
                    "embed_text": f"{tech_obj.get('name', '')} {tech_obj.get('description', '')[:300]}",
                })

            # --- B. TỰ ĐỘNG TRÍCH XUẤT SOFTWARE MAPPINGS (ĐỘNG) ---
            logger.info("Building dynamic Software-to-Technique mapping from STIX relationships...")
            software_list = mitre_data.get_software(remove_revoked_deprecated=True)
            self._software_mapping = {}
            
            for sw in software_list:
                sw_name = sw.get("name", "").lower()
                techs_used = mitre_data.get_techniques_used_by_software(sw.id)
                
                mapped_t_codes = []
                for t_dict in techs_used:
                    for ref in t_dict["object"].get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            mapped_t_codes.append(ref.get("external_id"))
                
                if mapped_t_codes:
                    unique_codes = list(set(mapped_t_codes))
                    self._software_mapping[sw_name] = unique_codes
                    
                    # Thêm cả các bí danh (Aliases) của tool (Ví dụ: APT29 = Cozy Bear)
                    if "x_mitre_aliases" in sw:
                        for alias in sw["x_mitre_aliases"]:
                            self._software_mapping[alias.lower()] = unique_codes

            # Cache lại cả 2 bộ dữ liệu
            ATTCK_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(ATTCK_CACHE_PATH, "w") as f:
                json.dump({
                    "techniques": self._techniques,
                    "software_mapping": self._software_mapping
                }, f, indent=2)
            logger.info(f"Cached {len(self._techniques)} techniques and {len(self._software_mapping)} software mappings.")

        except Exception as e:
            logger.error(f"Failed to load ATT&CK data: {e}")
            self._techniques = self._get_fallback_techniques()
            self._software_mapping = {}

    def _build_embeddings(self):
        """Build embeddings cho tất cả techniques."""
        if self._technique_embeddings is not None:
            return

        self._load_model()
        self._load_attck_data()

        logger.info(f"Building embeddings for {len(self._techniques)} techniques...")
        texts = [t["embed_text"] for t in self._techniques]
        self._technique_embeddings = self._model.encode(
            texts,
            batch_size=32,
            show_progress_bar=True,
            normalize_embeddings=True,  # Cosine similarity = dot product khi normalized
        )
        logger.info("Embeddings built")

    # ĐÃ ĐƯỢC CẬP NHẬT THÊM THAM SỐ ner_entities
    def map(self, text: str, top_k: Optional[int] = None, ner_entities: list[str] = None) -> ATTCKMapperResult:
        """
        Map text → ATT&CK techniques.
        Returns top-k techniques sorted by confidence.
        """
        k = top_k or self.top_k

        # 1. Check direct MITRE ID mention
        direct_matches = self._extract_direct_ids(text)
        
        self._load_attck_data() # Đảm bảo data đã load

        # 2. TÍNH NĂNG MỚI: Check direct LOLBin mapping từ NER Pipeline
        if ner_entities:
            for ent in ner_entities:
                tool = ent.lower()
                if tool in KNOWN_LOLBIN_MAPPING:
                    tech_id = KNOWN_LOLBIN_MAPPING[tool]
                    # Kiểm tra xem technique này đã được add chưa
                    if not any(m.technique_id == tech_id for m in direct_matches):
                        # Lấy thông tin từ data MITRE đã load
                        tech_info = next((t for t in self._techniques if t["id"] == tech_id), None)
                        if tech_info:
                            direct_matches.append(TechniqueMatch(
                                technique_id=tech_id,
                                technique_name=tech_info["name"],
                                tactic=tech_info["tactics"][0] if tech_info["tactics"] else "Unknown",
                                confidence=0.95, # Đặt điểm cao tuyệt đối vì NER đã bóc chính xác
                                description=tech_info["description"][:200],
                            ))

        # 3. Semantic similarity
        self._build_embeddings()
        query_embedding = self._model.encode(
            [text],
            normalize_embeddings=True,
        )[0]

        # Cosine similarity = dot product (vì đã normalize)
        similarities = np.dot(self._technique_embeddings, query_embedding)
        top_indices = np.argsort(similarities)[::-1][:k * 2]  # Get 2x để filter

        semantic_matches = []
        for idx in top_indices:
            score = float(similarities[idx])
            if score < self.confidence_threshold:
                continue
            tech = self._techniques[idx]
            semantic_matches.append(TechniqueMatch(
                technique_id=tech["id"],
                technique_name=tech["name"],
                tactic=tech["tactics"][0] if tech["tactics"] else "Unknown",
                confidence=score,
                description=tech["description"][:200],
            ))

        # 4. Merge direct + semantic, deduplicate
        all_matches = {}
        for m in direct_matches:
            all_matches[m.technique_id] = m
        for m in semantic_matches:
            if m.technique_id not in all_matches:
                all_matches[m.technique_id] = m

        sorted_matches = sorted(
            all_matches.values(),
            key=lambda x: x.confidence,
            reverse=True,
        )[:k]

        result = ATTCKMapperResult(matches=sorted_matches)
        if sorted_matches:
            result.primary = sorted_matches[0]

        logger.info(
            f"ATT&CK mapping: {len(sorted_matches)} techniques, "
            f"primary={result.primary.technique_id if result.primary else 'None'}"
        )
        return result

    def _extract_direct_ids(self, text: str) -> list[TechniqueMatch]:
        """Extract MITRE IDs được nhắc trực tiếp trong text."""
        import re
        pattern = re.compile(r'\bT(\d{4})(?:\.(\d{3}))?\b')
        matches = []
        for m in pattern.finditer(text):
            tech_id = f"T{m.group(1)}"
            if m.group(2):
                tech_id += f".{m.group(2)}"

            # Lookup trong techniques list
            tech_info = next(
                (t for t in self._techniques if t["id"] == tech_id),
                None,
            )
            if tech_info:
                matches.append(TechniqueMatch(
                    technique_id=tech_id,
                    technique_name=tech_info["name"],
                    tactic=tech_info["tactics"][0] if tech_info["tactics"] else "",
                    confidence=1.0,  # Direct mention = max confidence
                ))
        return matches

    def _get_fallback_techniques(self) -> list[dict]:
        """Top 10 techniques thường gặp nhất - fallback khi không có internet."""
        return [
            {"id": "T1059.001", "name": "PowerShell", "tactics": ["Execution"],
             "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
             "embed_text": "PowerShell command execution scripting"},
            {"id": "T1105", "name": "Ingress Tool Transfer", "tactics": ["Command And Control"],
             "description": "Adversaries may transfer tools or files from external systems.",
             "embed_text": "download payload certutil bitsadmin file transfer"},
            {"id": "T1071", "name": "Application Layer Protocol", "tactics": ["Command And Control"],
             "description": "Adversaries may communicate using application layer protocols.",
             "embed_text": "C2 command control HTTP HTTPS DNS communication"},
        ]