import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
import httpx

load_dotenv()

API_KEY = os.getenv("DASHSCOPE_API_KEY")
API_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"

async def run_llm_test():
    if not API_KEY:
        print("请先在 .env 文件中配置 DASHSCOPE_API_KEY")
        return
    
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": "qwen3.6-plus",
        "messages": [
            {"role": "system", "content": "你是一个安全专家助手。"},
            {"role": "user", "content": "什么是 SQL 注入？"}
        ],
        "max_tokens": 500
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{API_BASE_URL}/chat/completions",
                headers=headers,
                json=data,
                timeout=30
            )
            response.raise_for_status()
            result = response.json()
            answer = result["choices"][0]["message"]["content"]
            print("LLM 回复:")
            print(answer)
    except Exception as e:
        print(f"调用失败: {e}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(run_llm_test())
