"""
Chạy: python -m test_master_flow
Kịch bản test End-to-End toàn bộ Giai đoạn 1 của Automated Detection Engine.
"""
import os
import fitz  # PyMuPDF
from pathlib import Path

# Import toàn bộ các module lõi của hệ thống
from src.extraction.ioc_engine import IOCExtractor
from src.extraction.ner_pipeline import SecurityNERPipeline
from src.mapping.attack_mapper import ATTCKMapper
from src.mapping.rag_engine import RAGEngine
from src.generators.sigma_generator import SigmaGenerator, GenerationContext

def read_cti_pdf(pdf_path: str) -> str:
    """Đọc toàn bộ text từ một file PDF CTI thật và làm sạch."""
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"Không tìm thấy file PDF tại: {pdf_path}")
    
    doc = fitz.open(pdf_path)
    text = "\n".join([page.get_text("text") for page in doc])
    doc.close()
    
    # THÊM DÒNG NÀY: Thay thế xuống dòng bằng khoảng trắng để nối liền câu
    import re
    clean_text = re.sub(r'\s+', ' ', text)
    return clean_text
# def read_cti_image(image_path: str) -> str:
#     """
#     Yêu cầu cài đặt thêm: pip install pytesseract Pillow
#     Và cài đặt Tesseract Engine trên OS (Windows/Linux).
#     """
#     try:
#         import pytesseract
#         from PIL import Image
#         return pytesseract.image_to_string(Image.open(image_path))
#     except ImportError:
#         return "[!] Thiếu thư viện pytesseract hoặc Pillow để đọc ảnh."

def run_full_pipeline(cti_text: str, source_name: str = "CTI_Report"):
    print("\n" + "="*60)
    print(f" BẮT ĐẦU PIPELINE XỬ LÝ: {source_name}")
    print("="*60)

    # ---------------------------------------------------------
    # 1. IOC EXTRACTION
    # ---------------------------------------------------------
    print("\n[*] BƯỚC 1: Trích xuất IOCs...")
    ioc_engine = IOCExtractor()
    ioc_result = ioc_engine.extract_from_text(cti_text, source=source_name)
    for field_name in ioc_result.__dataclass_fields__:
        if field_name == "source": continue
        values = getattr(ioc_result, field_name)
        if values:
            print(f"  + {field_name.upper()}: {values}")
    print(f" -> Đã tìm thấy {ioc_result.total_count} IOCs.")
    if ioc_result.ips: print(f"    + IPs: {ioc_result.ips}")
    if ioc_result.domains: print(f"    + Domains: {ioc_result.domains}")
    if ioc_result.file_paths: print(f"    + Paths: {ioc_result.file_paths}")

    # ---------------------------------------------------------
    # 2. NER PIPELINE
    # ---------------------------------------------------------
    print("\n[*] BƯỚC 2: Trích xuất Thực thể Bảo mật (NER)...")
    ner = SecurityNERPipeline(
        use_securebert=True, # Đang tắt để test nhanh
        use_gliner=True      # Bật lên True nếu bạn đã cài xong phiên bản không lỗi
    )
    ner_result = ner.extract(cti_text)
    print(f" -> {ner_result.to_context_string()}")

    # ---------------------------------------------------------
    # 3. ATT&CK MAPPING (Có hỗ trợ từ NER)
    # ---------------------------------------------------------
    print("\n[*] BƯỚC 3: Ánh xạ MITRE ATT&CK (Semantic + NER Boost)...")
    mapper = ATTCKMapper(top_k=3)
    
    # TRUYỀN TOÀN BỘ THỰC THỂ NER BẮT ĐƯỢC VÀO
    all_ner_entities = (
        ner_result.lolbins + 
        ner_result.tools + 
        ner_result.malware_names + 
        ner_result.threat_actors + 
        ner_result.campaigns
    )
    
    mapping_result = mapper.map(
        text=cti_text[:2000],  # Chỉ lấy 2000 ký tự đầu cho Vector quét Semantic
        ner_entities=all_ner_entities # NER Boost sẽ cân phần còn lại
    )
    technique_ids = []
    if mapping_result.primary:
        print(f" -> Kỹ thuật chính: {mapping_result.primary.technique_id} - {mapping_result.primary.technique_name} (Độ tin cậy: {mapping_result.primary.confidence:.2f})")
    for match in mapping_result.matches:
        technique_ids.append(match.technique_id)
        
    sigma_tags = mapping_result.get_sigma_tags()
    print(f" -> Sigma Tags đề xuất: {sigma_tags}")

   # ---------------------------------------------------------
    # 4. RAG 2 TẦNG (Vector Retrieval + Reranker)
    # ---------------------------------------------------------
    print("\n[*] BƯỚC 4: RAG - Tìm kiếm Sigma Rules tương đồng...")
    rag = RAGEngine(use_reranker=True)
    if rag._collection is None or rag._collection.count() == 0:
        rag.ingest_rules() 
    
    # ÉP RAG PHẢI TÌM QUANH CÁC THỰC THỂ NER ĐÃ TÌM THẤY
    rag_query = f"Detect attacks involving malware or tools: {', '.join(ner_result.malware_names + ner_result.tools)}"
    print(f" -> Query cho RAG: {rag_query}")
    
    retrieved_rules_objs = rag.retrieve(rag_query)
    retrieved_rules_yaml = [r.rule_yaml for r in retrieved_rules_objs]
    
    print(f" -> Đã tìm thấy {len(retrieved_rules_objs)} rules liên quan làm ngữ cảnh.")
    for i, r in enumerate(retrieved_rules_objs):
        print(f"    + Top {i+1}: {r.metadata.get('title')} (Score: {r.rerank_score:.4f})")

    # ---------------------------------------------------------
    # 5. LLM SIGMA GENERATOR (Chạy qua LLM)
    # ---------------------------------------------------------
    print("\n[*] BƯỚC 5: Gọi LLM (Generator) sinh Sigma Rule...")
    
    # Đóng gói ngữ cảnh truyền cho LLM
    ctx = GenerationContext(
        input_text=cti_text[:4000], # LLM chỉ đọc tóm tắt đoạn đầu để hiểu bối cảnh (APT29)
        input_type="pdf_excerpt",
        attck_techniques=technique_ids, # <-- Danh sách Txxxx chính xác bóc từ cuối PDF
        ioc_data=ioc_result.to_dict(),
        retrieved_rules=retrieved_rules_yaml
    )
    
    generator = SigmaGenerator()
    try:
        # Lưu ý: Hàm này yêu cầu bạn đã setup LLM_PROVIDER và API_KEY trong file .env
        sigma_result = generator.generate_sync(ctx)
        
        if sigma_result.valid:
            print(f" -> [THÀNH CÔNG] Rule được LLM sinh ra đạt {sigma_result.quality_score}/10 điểm!")
            print("\n" + "="*40 + " KẾT QUẢ SIGMA RULE " + "="*40)
            print(sigma_result.rule_yaml)
            print("="*100)
        else:
            print(f" -> [THẤT BẠI] LLM không sinh được rule hợp lệ. Lỗi: {sigma_result.explanation}")
            
    except Exception as e:
        print(f" -> [BỎ QUA] Lỗi khi gọi LLM (Kiểm tra lại API Key trong file .env): {e}")


if __name__ == "__main__":
    import logging
    # Ẩn bớt log rác của thư viện
    logging.getLogger("sentence_transformers").setLevel(logging.WARNING)
    logging.getLogger("src.mapping.rag_engine").setLevel(logging.WARNING)
    
    # ====================================================================
    # KỊCH BẢN 1: TEST VỚI RAW TEXT (Fallback nếu không có PDF)
    # ====================================================================
    sample_text = r"""
    Vào ngày 15/05/2026, nhóm APT29 đã thực hiện chiến dịch tấn công nhắm vào máy chủ Exchange (CVE-2021-44228).
    Kẻ tấn công sử dụng PowerShell.exe để thực thi mã độc base64, sau đó dùng certutil.exe với cờ -urlcache 
    để tải payload từ hxxps://malicious-c2[.]com/stage2.exe.
    Tiến trình tạo ra registry key tại HKLM\Software\Microsoft\Windows\CurrentVersion\Run\MalService để persistence.
    """
    
    # run_full_pipeline(sample_text, source_name="Text_Sample")
    
    # ====================================================================
    # KỊCH BẢN 2: TEST VỚI FILE PDF SỐNG
    # ====================================================================
    # Hãy copy một file PDF thật (ví dụ báo cáo của Mandiant, CISA...) 
    # vào thư mục data/raw_cti/ và đổi tên biến pdf_path ở dưới
    
    pdf_path = "./data/raw_cti/WhiteHat.vn.pdf"
    
    try:
            pdf_text = read_cti_pdf(pdf_path)
            
            
            
            # TRUYỀN FULL TEXT VÀO PIPELINE (CHÚ Ý: XOÁ HẾT CÁC [:] Ở ĐÂY VÀ TRONG HÀM BÊN TRÊN)
            run_full_pipeline(pdf_text, source_name=Path(pdf_path).name)
    except Exception as e:
            print(f"Lỗi khi xử lý file PDF: {e}")
