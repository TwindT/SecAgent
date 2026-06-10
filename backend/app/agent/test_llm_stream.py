"""LLM 流式调用测试脚本"""
import sys
sys.path.insert(0, '.')

from app.agent.llm import LLMClient

def test_stream():
    print('=== 流式调用测试 ===')
    client = LLMClient()
    full = ''
    for chunk in client.chat_stream([
        {'role': 'system', 'content': '你是一个安全专家助手。'},
        {'role': 'user', 'content': '用一句话解释什么是 XSS 攻击。'}
    ]):
        delta = chunk['delta']
        if delta:
            print(delta, end='', flush=True)
            full += delta
        if chunk['finish_reason']:
            print()
            print(f'--- 结束: {chunk["finish_reason"]} ---')
            print(f'Token 用量: {chunk["usage"]}')

    print()
    print(f'完整回复: {full}')
    print('=== 流式调用成功 ===')

if __name__ == '__main__':
    test_stream()
