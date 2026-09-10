"""
src/mapping/rag_engine.py
──────────────────────────────
RAG 2 Tầng cho Sigma Rules:
Stage 1: Vector Retrieval (ChromaDB + Dense Embedding)
Stage 2: Cross-Encoder Reranking
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

# Các import cũ giữ nguyên
import logging
import yaml
from dataclasses import dataclass
from typing import Optional, List
from src.config.settings import get_settings, VectorDB
# ...

logger = logging.getLogger(__name__)


@dataclass
class RetrievedRule:
    rule_yaml: str
    metadata: dict
    retrieval_score: float = 0.0
    rerank_score: float = 0.0


class RAGEngine:
    """
    RAG Engine 2 tầng (Retrieve & Rerank) chuyên dụng cho SigmaHQ rules.
    """
    def __init__(self, use_reranker: bool = True):
        self.settings = get_settings()
        self.use_reranker = use_reranker
        
        self._embedding_model = None
        self._reranker_model = None
        self._db_client = None
        self._collection = None

    def _load_models(self):
        """Lazy load các mô hình AI để tiết kiệm RAM."""
        # 1. Load Embedding Model
        if self._embedding_model is None:
            from sentence_transformers import SentenceTransformer
            logger.info(f"Loading embedding model: {self.settings.embedding_model}")
            self._embedding_model = SentenceTransformer(self.settings.embedding_model)

        # 2. Load Reranker Model (Cross-Encoder)
        if self.use_reranker and self._reranker_model is None:
            from sentence_transformers import CrossEncoder
            logger.info(f"Loading reranker model: {self.settings.reranker_model}")
            # CrossEncoder chấm điểm trực tiếp cặp (query, document)
            self._reranker_model = CrossEncoder(self.settings.reranker_model)

    def _init_db(self):
        """Khởi tạo kết nối Vector DB (Mặc định: ChromaDB)."""
        if self._collection is not None:
            return

        self.settings.ensure_dirs()
        
        if self.settings.vector_db == VectorDB.CHROMADB:
            import chromadb
            # Dùng PersistentClient để lưu data xuống ổ cứng
            self._db_client = chromadb.PersistentClient(path=self.settings.chroma_persist_dir)
            self._collection = self._db_client.get_or_create_collection(
                name="sigmahq_rules",
                metadata={"hnsw:space": "cosine"} # Ưu tiên Cosine similarity cho BGE model
            )
            logger.info(f"ChromaDB initialized at {self.settings.chroma_persist_dir}")
        else:
            raise NotImplementedError("Hiện tại GĐ1 chỉ support ChromaDB cho local dev.")

    def ingest_rules(self, rules_dir: Optional[str] = None):
        """
        Đọc các file .yml SigmaHQ, nhúng (embed) và lưu vào VectorDB.
        """
        self._init_db()
        self._load_models()

        target_dir = Path(rules_dir or self.settings.sigmahq_rules_dir)
        if not target_dir.exists():
            logger.warning(f"Thư mục Sigma rules không tồn tại: {target_dir}")
            return

        yaml_files = list(target_dir.rglob("*.yml")) + list(target_dir.rglob("*.yaml"))
        if not yaml_files:
            logger.warning(f"Không tìm thấy file Sigma (.yml) nào trong {target_dir}")
            return

        logger.info(f"Đang xử lý và indexing {len(yaml_files)} Sigma rules...")
        
        # Batching để tránh tràn RAM
        BATCH_SIZE = 100
        docs, metadatas, ids, raw_yamls = [], [], [], []

        for i, filepath in enumerate(yaml_files):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    raw_yaml = f.read()
                    
                    # SỬA Ở ĐÂY: Dùng safe_load_all để đọc file có nhiều document (---)
                    parsed_docs = list(yaml.safe_load_all(raw_yaml))
                    # Lấy document cuối cùng (thường là phần chứa rule chính)
                    parsed = parsed_docs[-1] if parsed_docs else {}
                
                if not isinstance(parsed, dict) or "title" not in parsed:
                    continue

                # Tạo chuỗi văn bản giàu ngữ nghĩa để AI dễ nhận diện (Embed Text)
                embed_text = (
                    f"Title: {parsed.get('title', '')}\n"
                    f"Description: {parsed.get('description', '')}\n"
                    f"Logsource: {parsed.get('logsource', {})}\n"
                    f"Tags: {', '.join(parsed.get('tags', []))}"
                )

                rule_id = str(parsed.get("id", filepath.name))
                
                docs.append(embed_text)
                raw_yamls.append(raw_yaml)
                ids.append(rule_id)
                metadatas.append({
                    "title": str(parsed.get('title', '')),
                    "filename": str(filepath.name),
                    "rule_yaml": raw_yaml # Lưu raw yaml vào metadata để LLM đọc
                })

                if len(docs) >= BATCH_SIZE or i == len(yaml_files) - 1:
                    embeddings = self._embedding_model.encode(docs, normalize_embeddings=True).tolist()
                    self._collection.upsert(
                        ids=ids,
                        embeddings=embeddings,
                        documents=docs,
                        metadatas=metadatas
                    )
                    docs, metadatas, ids, raw_yamls = [], [], [], []

            except Exception as e:
                
                logger.error(f"Lỗi khi đọc/nhúng file {filepath}: {e}")

        logger.info("Indexing hoàn tất!")

    def retrieve(self, query: str) -> List[RetrievedRule]:
        """
        Thực hiện RAG 2 tầng để lấy ra các rule liên quan nhất.
        """
        self._init_db()
        self._load_models()

        if self._collection.count() == 0:
            logger.warning("VectorDB trống! Vui lòng gọi ingest_rules() trước.")
            return []

        # -------------------------------------------------------------
        # STAGE 1: VECTOR RETRIEVAL (Truy xuất thô)
        # -------------------------------------------------------------
        query_embedding = self._embedding_model.encode(query, normalize_embeddings=True).tolist()
        
        top_k_retrieve = self.settings.rag_top_k_retrieve # Thường là 20
        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k_retrieve
        )

        stage1_rules = []
        # ChromaDB trả về list các list, ta lấy phần tử [0]
        if results['ids'] and results['ids'][0]:
            for i in range(len(results['ids'][0])):
                rule = RetrievedRule(
                    rule_yaml=results['metadatas'][0][i]['rule_yaml'],
                    metadata=results['metadatas'][0][i],
                    # ChromaDB trả về distance (khoảng cách), chuyển thành score: 1 - distance
                    retrieval_score=1.0 - results['distances'][0][i] 
                )
                stage1_rules.append(rule)

        if not self.use_reranker or not stage1_rules:
            return stage1_rules[:self.settings.rag_top_k_rerank]

        # -------------------------------------------------------------
        # STAGE 2: CROSS-ENCODER RERANKING (Xếp hạng tinh)
        # -------------------------------------------------------------
        # Tạo danh sách các cặp (Query, Rule Document) để đưa vào Reranker
        # Dùng title và phần đầu của rule để chấm điểm ngữ nghĩa chéo
        cross_inp = [[query, r.metadata['title']] for r in stage1_rules]
        
        rerank_scores = self._reranker_model.predict(cross_inp)

        for i, score in enumerate(rerank_scores):
            stage1_rules[i].rerank_score = float(score)

        # Sắp xếp lại theo điểm rerank_score từ cao xuống thấp
        filtered_rules = [r for r in stage1_rules if r.rerank_score > 0.2]
        
        filtered_rules.sort(key=lambda x: x.rerank_score, reverse=True)
        return filtered_rules[:self.settings.rag_top_k_rerank]
    
        # stage1_rules.sort(key=lambda x: x.rerank_score, reverse=True)

        # # Trả về Top K cuối cùng (Thường là 3 - 5)
        # top_k_rerank = self.settings.rag_top_k_rerank
        # return stage1_rules[:top_k_rerank]


# ── Quick test ───────────────────────────────────────────────
if __name__ == "__main__":
    import os
    import logging
    
    # Bật hiển thị log ra terminal
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    
    print("\n" + "="*60)
    print(" NẠP DỮ LIỆU SIGMAHQ THẬT VÀO VECTOR DATABASE (CHROMADB)")
    print("="*60)

    engine = RAGEngine(use_reranker=True)
    
    # 1. ĐỌC VÀ NHÚNG (EMBED) HÀNG NGÀN RULE TỪ GITHUB
    print("[*] 1. Đang quét và nhúng các rule thực tế vào ChromaDB...")
    print("Lưu ý: Quá trình này sẽ mất khoảng 3 - 10 phút tùy tốc độ CPU vì phải đọc >3000 rules.")
    print("Nhưng bạn CỈ CẦN CHẠY 1 LẦN DUY NHẤT, dữ liệu sẽ được lưu cứng vào ổ đĩa.\n")
    
    # Gọi hàm ingest, nó sẽ dùng rglob("*.yml") tự động quét sâu vào các thư mục con
    engine.ingest_rules()

    # 2. Test Truy vấn với CTI thật
    test_query = "Kẻ tấn công sử dụng PowerShell.exe để thực thi mã độc base64, sau đó dùng certutil.exe với cờ -urlcache để tải payload"
    
    print(f"\n[*] 2. Đang truy vấn RAG cho query:\n'{test_query}'")
    
    results = engine.retrieve(test_query)
    
    print("\n" + "="*50)
    print(" KẾT QUẢ TOP 5 RULES (SIGMAHQ) SAU KHI RERANK")
    print("="*50)
    for i, r in enumerate(results):
        print(f"Hạng {i+1}: {r.metadata.get('title')}")
        print(f"   + File: {r.metadata.get('filename')}")
        print(f"   + Stage 1 (Vector Score): {r.retrieval_score:.4f}")
        print(f"   + Stage 2 (Rerank Score): {r.rerank_score:.4f}")
        print("-" * 40)