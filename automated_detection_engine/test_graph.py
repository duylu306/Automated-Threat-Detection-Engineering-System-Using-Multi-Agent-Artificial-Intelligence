import asyncio
import fitz  # PyMuPDF
import re
from pathlib import Path
from src.workflow.agent_graph import build_agent_graph

def read_cti_pdf(pdf_path: str) -> str:
    """Đọc và làm sạch text từ PDF CTI thật."""
    if not Path(pdf_path).exists():
        raise FileNotFoundError(f"Không tìm thấy: {pdf_path}")
    doc = fitz.open(pdf_path)
    text = "\n".join([page.get_text("text") for page in doc])
    doc.close()
    return re.sub(r'\s+', ' ', text)

async def test_real_cti_graph():
    print("="*50)
    print(" STRESS TEST MULTI-AGENT VỚI REAL CTI")
    print("="*50)

    # Đọc báo cáo CTI thật (thay đường dẫn bằng file PDF của bạn)
    # Có thể dùng file "automated_detection_engine/debug_pdf_text.txt" nếu muốn test text thô
    cti_text = read_cti_pdf("./data/raw_cti/38_page.pdf") 
    print(f"[*] Đã đọc báo cáo CTI: {len(cti_text)} ký tự.")

    graph = build_agent_graph()

    initial_state = {
        "cti_text": cti_text,
        "source_name": "test_CTI",
        "attempts": 0,
        "ioc_data": {},
        "generation_tasks": [],
        "generated_rules": [],
        "validated_rules": []
    }

    print("\n[*] Đang chạy stream qua các Agent...")
    
    async for event in graph.astream(initial_state):
        for node_name, node_state in event.items():
            print(f"\n--- [NODE COMPLETED: {node_name.upper()}] ---")
            
            if node_name == "planner":
                tasks = node_state.get("generation_tasks", [])
                print(f"-> Planner đã phân rã báo cáo thành {len(tasks)} tasks sinh rule.")
                
            elif node_name == "generator":
                rules = node_state.get("generated_rules", [])
                print(f"-> Generator đã sinh {len(rules)} rules.")
                
            elif node_name == "critic":
                validations = node_state.get("validated_rules", [])
                for idx, v in enumerate(validations):
                    print(f"\n================ RULE {idx+1} (Hợp lệ: {v.get('valid')} | Điểm: {v.get('score')}/10) ================")
                    # In toàn bộ nội dung rule YAML
                    print(v.get("rule_yaml", "Không có nội dung rule!"))
                    print("========================================================================================\n")

            elif node_name == "fixer":
                print("-> Fixer đang điều chỉnh prompt để Generator sửa lỗi...")

            elif node_name == "consolidator":
                consolidated_rules = node_state.get("validated_rules", [])
                print("\n" + "*"*60)
                print(f" KẾT QUẢ CUỐI CÙNG SAU KHI GỘP ({len(consolidated_rules)} Rules)")
                print("*"*60)
                for idx, v in enumerate(consolidated_rules):
                    print(f"\n--- FINAL RULE {idx+1} (Hợp lệ: {v.get('valid')} | Điểm: {v.get('score')}/10) ---")
                    print(v.get("rule_yaml", ""))

if __name__ == "__main__":
    asyncio.run(test_real_cti_graph())