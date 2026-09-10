"""
src/workflow/agent_graph.py
──────────────────────────────
Điều phối Multi-Agent bằng LangGraph StateGraph.
Mô hình: Diverge-then-Converge với Self-Correction Loop.
"""
import os
import sys
import logging
from typing import List, Dict, Any, TypedDict, Annotated
from pathlib import Path

# Đảm bảo import được các module từ thư mục gốc
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from langgraph.graph import StateGraph, END

from src.extraction.ioc_engine import IOCExtractor
from src.extraction.ner_pipeline import SecurityNERPipeline
from src.mapping.attack_mapper import ATTCKMapper
from src.mapping.rag_engine import RAGEngine
from src.generators.sigma_generator import SigmaGenerator, GenerationContext
from src.validation.sigma_validator import SigmaValidator

logger = logging.getLogger(__name__)

# 1. Định nghĩa trạng thái của Hệ thống (Graph State)
from typing import TypedDict, List, Dict, Any

class AgentState(TypedDict):
    cti_text: str
    source_name: str
    ioc_data: dict
    # Trạng thái đa luồng
    generation_tasks: List[Dict[str, Any]]
    generated_rules: List[str]
    validated_rules: List[dict]
    attempts: int


# ====================================================================
# ĐỊNH NGHĨA CÁC NODE (AGENTS)
# ====================================================================

async def planner_agent(state: AgentState) -> Dict[str, Any]:
    """Agent 1: Planner - Thu thập, chuẩn hóa, phân tích TTPs và RAG."""
    logger.info("--- STARTING PLANNER AGENT ---")
    text = state["cti_text"]
    source = state["source_name"]
    
    # Chạy luồng phân tích song song (Diverge)
    ioc_eng = IOCExtractor()
    ioc_result = ioc_eng.extract_from_text(text, source=source)
    
    ner_eng = SecurityNERPipeline(use_securebert=True, use_gliner=True, confidence_threshold=0.3)
    ner_result = ner_eng.extract(text)
    
    mapper = ATTCKMapper(top_k=3)
    all_entities = ner_result.lolbins + ner_result.tools + ner_result.malware_names + ner_result.threat_actors + ner_result.campaigns
    mapping_result = mapper.map(text=text, ner_entities=all_ner_entities if 'all_ner_entities' in locals() else all_entities)
    
    tech_ids = [m.technique_id for m in mapping_result.matches]
    
    unique_techniques = list({m.technique_id: m for m in mapping_result.matches}.values())
    
    rag_eng = RAGEngine(use_reranker=True)
    
    extracted_entities = ner_result.tools + ner_result.lolbins + ner_result.malware_names
    entities_context = f" Involving tools/malware: {', '.join(extracted_entities)}." if extracted_entities else ""

    # Tạo danh sách các task song song với RAG query chi tiết hơn
    generation_tasks = []
    for tech in unique_techniques:
        # Nhồi thêm entity vào câu hỏi RAG để tìm rule sát với ngữ cảnh thực tế nhất
        rag_query = f"Sigma rule to detect {tech.technique_name} ({tech.technique_id}).{entities_context}"
        
        # Chỉ lấy text yaml của các rule vượt qua được bộ lọc
        rag_context = [r.rule_yaml for r in rag_eng.retrieve(rag_query)]
        
        generation_tasks.append({
            "technique_id": tech.technique_id,
            "technique_name": tech.technique_name,
            "rag_context": rag_context
        })
    
    return {
        "ioc_data": ioc_result.to_dict(),
        "generation_tasks": generation_tasks,
        "attempts": 0
    }


import asyncio

async def generator_agent(state: dict) -> dict:
    generator = SigmaGenerator()
    
    # Đóng gói ngữ cảnh riêng cho từng task
    coroutines = [
        generator.generate(GenerationContext(
            input_text=state["cti_text"],
            input_type="pdf_excerpt",
            attck_techniques=[task["technique_id"]],
            ioc_data=state.get("ioc_data", {}),
            retrieved_rules=task["rag_context"]
        ))
        for task in state["generation_tasks"]
    ]
    
    # Kích hoạt LLM sinh rule song song
    results = await asyncio.gather(*coroutines)
    
    return {
        "generated_rules": [res.rule_yaml for res in results if res.rule_yaml],
        "attempts": state.get("attempts", 0) + 1
    }


async def critic_agent(state: dict) -> dict:
    validator = SigmaValidator()
    
    # Xác thực toàn bộ rule
    validations = [validator.validate(rule) for rule in state["generated_rules"]]
    
    # Phân loại kết quả
    validated_rules = [
        {
            "rule_yaml": val.fixed_yaml or rule,
            "score": val.score,
            "valid": val.valid,
            "errors": [issue.message for issue in val.issues if issue.severity == "error"]
        }
        for rule, val in zip(state["generated_rules"], validations)
    ]
    
    return {
        "validated_rules": validated_rules
    }




# -------------------------------------------------------------
# ĐIỀU HƯỚNG ĐỒ THỊ (Conditional Routing)
# -------------------------------------------------------------
def route_after_critic(state: dict) -> str:
    """Quyết định xem có cần sửa lỗi tiếp hay chuyển sang hợp nhất."""
    validated_rules = state.get("validated_rules", [])
    attempts = state.get("attempts", 0)
    
    needs_fix = False
    lowest_score = 10
    for v in validated_rules:
        score = v.get("score", 0)
        if not v.get("valid") or score < 7:
            needs_fix = True
        if score < lowest_score:
            lowest_score = score
            
    if not needs_fix:
        print(" -> [CONSOLIDATE] Tất cả rules hợp lệ. Chuyển sang bước hậu xử lý và hợp nhất...")
        return "consolidator"
    
    if attempts >= 3:
        print(f" -> [CONSOLIDATE] Đã đạt giới hạn sửa lỗi ({attempts} lần). Chuyển sang hợp nhất kết quả hiện có.")
        return "consolidator"
        
    print(f" -> [FIX] Phát hiện rule chưa đạt chuẩn ({lowest_score}/10). Chuyển sang Fixer Agent...")
    return "fixer"


async def fixer_agent_node(state: dict) -> dict:
    """Agent 4: Khắc phục lỗi và điều chỉnh chiến lược sinh rule."""
    attempts = state.get('attempts', 0)
    print(f"\n[*] BƯỚC ĐIỀU CHỈNH (Fixer) - Vòng {attempts}:")
    
    # Gom tất cả các lỗi từ các rule bị fail
    all_errors = []
    for idx, val in enumerate(state.get("validated_rules", [])):
        if not val.get("valid") or val.get("score", 0) < 7:
            errors = val.get("errors", [])
            if errors:
                all_errors.extend(errors)
            else:
                all_errors.append(f"Rule {idx + 1} score is too low ({val.get('score')}/10).")
                
    print(f"    + Danh sách lỗi cần sửa: {all_errors}")
    
    # Lấy text gốc
    original_text = state.get("cti_text", "")
    
    # Tránh việc nối chuỗi thông báo lỗi bị lặp lại nhiều lần ở các vòng tiếp theo
    if "=== CRITIC ERROR ALERT ===" in original_text:
        original_text = original_text.split("=== CRITIC ERROR ALERT ===")[0].strip()
        
    error_msg = "\n".join(all_errors)
    
    # Nhồi thêm thông báo lỗi vào cti_text để Generator đọc và tự sửa
    updated_text = (
        f"{original_text}\n\n"
        f"=== CRITIC ERROR ALERT ===\n"
        f"Your previous generated rules had the following errors:\n{error_msg}\n"
        f"Please regenerate and strictly fix these issues. Ensure valid YAML syntax."
    )
    
    # Cập nhật lại cti_text trong State
    return {"cti_text": updated_text}
from src.config.settings import get_settings, LLMProvider
import yaml

async def consolidator_agent(state: AgentState) -> Dict[str, Any]:
    """Agent 5: Consolidator - Duyệt lại toàn bộ danh sách, phát hiện dẫm chân hành vi và gộp rule."""
    logger.info("--- STARTING CONSOLIDATOR AGENT ---")
    validated_rules = state.get("validated_rules", [])
    
    valid_rules = [r for r in validated_rules if r.get("valid")]
    invalid_rules = [r for r in validated_rules if not r.get("valid")]
    
    if len(valid_rules) <= 1:
        return {"validated_rules": validated_rules}
        
    # Chuẩn bị dữ liệu đầu vào cho LLM
    rules_input = ""
    for idx, r in enumerate(valid_rules):
        rules_input += f"\n--- RULE {idx+1} ---\n{r['rule_yaml']}\n"
        
    # Lazy load LLM client từ cấu hình hệ thống
    settings = get_settings()
    llm = None
    provider = settings.llm_provider
    
    if provider == LLMProvider.OPENAI:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(model=settings.llm_model, temperature=0.1, api_key=settings.openai_api_key)
    elif provider == LLMProvider.ANTHROPIC:
        from langchain_anthropic import ChatAnthropic
        llm = ChatAnthropic(model=settings.llm_model, temperature=0.1, api_key=settings.anthropic_api_key)
    elif provider == LLMProvider.GOOGLE:
        from langchain_google_genai import ChatGoogleGenerativeAI
        llm = ChatGoogleGenerativeAI(model=settings.llm_model, temperature=0.1, google_api_key=settings.google_api_key)
    elif provider == LLMProvider.OLLAMA:
        from langchain_community.chat_models import ChatOllama
        llm = ChatOllama(model=settings.ollama_model, temperature=0.1, base_url=settings.ollama_base_url)
        
    if llm is None:
        return {"validated_rules": validated_rules}
        
    prompt = (
        "You are a Senior Detection Engineer specializing in Sigma rules.\n"
        "Review the following list of valid Sigma rules generated from the same threat intelligence report.\n"
        "Identify structural or logical redundancies (e.g., multiple network rules blocking the exact same IPs/domains under different MITRE tags).\n"
        "Merge redundant rules into a single comprehensive rule by combining titles, descriptions, and merging their lists of tags (union of tags).\n"
        "Output ONLY the final deduplicated raw YAML rules. If multiple unique rules remain, separate them with '---'. Do not include markdown code blocks or explanations.\n\n"
        f"=== VALIDATED SIGMA RULES ===\n{rules_input}"
    )
    
    try:
        from langchain_core.messages import HumanMessage
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        raw_output = response.content.strip()
        raw_output = raw_output.replace("```yaml", "").replace("```", "").strip()
        
        # Phân rã kết quả sau khi gộp từ LLM thành các document riêng biệt
        parsed_docs = list(yaml.safe_load_all(raw_output))
        
        new_validated_rules = []
        from src.validation.sigma_validator import SigmaValidator
        validator = SigmaValidator()
        
        for doc in parsed_docs:
            if not doc or not isinstance(doc, dict):
                continue
            rule_str = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
            val_res = validator.validate(rule_str)
            new_validated_rules.append({
                "rule_yaml": val_res.fixed_yaml or rule_str,
                "score": val_res.score,
                "valid": val_res.valid,
                "errors": [issue.message for issue in val_res.issues if issue.severity == "error"]
            })
            
        print(f" -> [CONSOLIDATOR] Đã tối ưu và gộp từ {len(valid_rules)} rules xuống còn {len(new_validated_rules)} rules.")
        return {"validated_rules": new_validated_rules + invalid_rules}
    except Exception as e:
        logger.error(f"Consolidation failed: {e}")
        return {"validated_rules": validated_rules}


# -------------------------------------------------------------
# XÂY DỰNG ĐỒ THỊ LANGGRAPH
# -------------------------------------------------------------
from langgraph.graph import StateGraph, END

def build_agent_graph():
    from langgraph.graph import StateGraph, END
    
    # Khởi tạo đồ thị với AgentState
    workflow = StateGraph(AgentState)
    
    # Định nghĩa các Node
    workflow.add_node("planner", planner_agent)
    workflow.add_node("generator", generator_agent)
    workflow.add_node("critic", critic_agent)
    workflow.add_node("fixer", fixer_agent_node)
    workflow.add_node("consolidator", consolidator_agent) # Node mới
    
    # Thiết lập các Cạnh (Edges) mặc định
    workflow.set_entry_point("planner")
    workflow.add_edge("planner", "generator")
    workflow.add_edge("generator", "critic")
    
    # Cạnh có điều kiện sau tầng Critic
    workflow.add_conditional_edges(
        "critic",
        route_after_critic,
        {
            "fixer": "fixer",
            "consolidator": "consolidator"
        }
    )
    
    workflow.add_edge("fixer", "generator")
    workflow.add_edge("consolidator", END) # Đích đến cuối cùng
    
    return workflow.compile()