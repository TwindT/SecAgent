import subprocess
import json
import tempfile
import os

def test_semgrep():
    test_code = """
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return execute_query(query)
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        temp_file = f.name
    
    try:
        result = subprocess.run(
            ["semgrep", "--json", "--lang=python", "--pattern=$X", temp_file],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print("Semgrep 扫描结果:")
            print(result.stdout)
        else:
            print(f"Semgrep 执行失败: {result.stderr}")
    except FileNotFoundError:
        print("Semgrep 未安装，请先安装: pip install semgrep")
    except subprocess.TimeoutExpired:
        print("Semgrep 执行超时")
    finally:
        os.unlink(temp_file)

if __name__ == "__main__":
    test_semgrep()
