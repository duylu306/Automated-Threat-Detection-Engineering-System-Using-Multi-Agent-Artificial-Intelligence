import asyncio
from src.generators.sigma_generator import SigmaGenerator, GenerationContext
# Kiểm tra lại đường dẫn import này trong file tests/test_phase1.py của cậu
from src.validation.sigma_validator import SigmaValidator 

async def main():
    # 1. Gọi Generator (Gemini) sinh rule
    print("[*] Đang gọi Generator (Gemini-2.5-Flash) sinh rule...")
    generator = SigmaGenerator()
    ctx = GenerationContext(
        input_text="Kẻ tấn công sử dụng certutil.exe với cờ -urlcache để tải mã độc từ http://malicious.com",
        attck_techniques=["T1105"]
    )
    gen_result = await generator.generate(ctx)
    rule_yaml = gen_result.rule_yaml
    
    print("\n=== SIGMA RULE GENERATED ===")
    print(rule_yaml)
    
    # 2. Gọi Critic (Validator) chấm điểm và kiểm tra cú pháp
    print("\n[*] Đang chuyển rule sang Critic Agent để kiểm tra và chấm điểm...")
    validator = SigmaValidator()
    
    # Gọi hàm validate (cậu check lại tên hàm trong class SigmaValidator của cậu, thường là validate hoặc validate_rule)
    val_result = validator.validate(rule_yaml) 
    
    print("\n=== CRITIC ASSESSMENT ===")
    print(f"Trạng thái cú pháp : {'HỢP LỆ' if val_result.valid else 'LỖI CÚ PHÁP'}")
    print(f"Điểm số chất lượng : {getattr(val_result, 'score', 'N/A')}/10")
    
    if not val_result.is_valid and hasattr(val_result, 'errors'):
        print(f"Chi tiết lỗi phát hiện: {val_result.errors}")

if __name__ == "__main__":
    asyncio.run(main())