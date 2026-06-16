"""Redis 连通性与功能测试脚本 — 验证 Docker 中的 Redis 是否正常运行

用法:
    python scripts/test_redis.py
    python scripts/test_redis.py --host 127.0.0.1 --port 6379 --db 0
"""

import argparse
import sys
import time


def test_redis(host: str, port: int, db: int, password: str | None = None):
    try:
        import redis
    except ImportError:
        print("[FAIL] redis 包未安装，请执行: pip install redis")
        sys.exit(1)

    print(f"正在连接 Redis {host}:{port} (db={db}) ...")

    try:
        r = redis.Redis(host=host, port=port, db=db, password=password, decode_responses=True)
    except Exception as e:
        print(f"[FAIL] 创建 Redis 连接失败: {e}")
        sys.exit(1)

    # ── 1. Ping 测试 ──
    print("\n[1/5] Ping 测试")
    try:
        pong = r.ping()
        if pong:
            print("  [OK] PONG")
        else:
            print("  [FAIL] ping 返回 False")
            sys.exit(1)
    except redis.ConnectionError as e:
        print(f"  [FAIL] 连接失败: {e}")
        print("  提示: 检查 Docker 容器是否运行 (docker ps)，端口是否映射正确")
        sys.exit(1)
    except redis.AuthenticationError as e:
        print(f"  [FAIL] 认证失败: {e}")
        print("  提示: 检查 Redis 是否设置了密码")
        sys.exit(1)

    # ── 2. 读写测试 ──
    print("\n[2/5] 读写测试")
    try:
        r.set("_test_key", "secagent_test", ex=60)
        val = r.get("_test_key")
        if val == "secagent_test":
            print("  [OK] SET/GET 正常")
        else:
            print(f"  [FAIL] 读取值不匹配: 期望 'secagent_test', 实际 '{val}'")
        r.delete("_test_key")
    except Exception as e:
        print(f"  [FAIL] 读写失败: {e}")

    # ── 3. Pub/Sub 测试（项目核心依赖） ──
    print("\n[3/5] Pub/Sub 测试")
    try:
        pubsub = r.pubsub()
        pubsub.subscribe("_test_channel")
        # 消费订阅确认消息
        pubsub.get_message(timeout=2)

        # 发布消息
        r.publish("_test_channel", "hello_secagent")

        # 接收消息
        msg = pubsub.get_message(timeout=3)
        if msg and msg["type"] == "message" and msg["data"] == "hello_secagent":
            print("  [OK] Pub/Sub 正常")
        else:
            print(f"  [FAIL] Pub/Sub 消息未收到或数据不匹配: {msg}")

        pubsub.unsubscribe("_test_channel")
        pubsub.close()
    except Exception as e:
        print(f"  [FAIL] Pub/Sub 测试失败: {e}")

    # ── 4. 模拟项目 task_steps 通道测试 ──
    print("\n[4/5] 模拟项目 task_steps 通道")
    try:
        test_channel = "task_steps_99999"
        pubsub = r.pubsub()
        pubsub.subscribe(test_channel)
        pubsub.get_message(timeout=2)

        import json
        test_step = {
            "step_num": 1,
            "type": "thought",
            "data": {"thought": "测试思考步骤"},
        }
        r.publish(test_channel, json.dumps(test_step, ensure_ascii=False))

        msg = pubsub.get_message(timeout=3)
        if msg and msg["type"] == "message":
            received = json.loads(msg["data"])
            if received.get("type") == "thought":
                print("  [OK] task_steps 通道正常")
            else:
                print(f"  [FAIL] 消息类型不匹配: {received}")
        else:
            print(f"  [FAIL] 未收到 task_steps 消息: {msg}")

        pubsub.unsubscribe(test_channel)
        pubsub.close()
    except Exception as e:
        print(f"  [FAIL] task_steps 通道测试失败: {e}")

    # ── 5. 服务器信息 ──
    print("\n[5/5] 服务器信息")
    try:
        info = r.info("server")
        print(f"  Redis 版本: {info.get('redis_version', '?')}")
        print(f"  运行模式: {info.get('redis_mode', '?')}")
        print(f"  操作系统: {info.get('os', '?')}")
        print(f"  已用内存: {info.get('used_memory_human', '?')}")
        print(f"  连接客户端数: {info.get('connected_clients', '?')}")
        print(f"  运行天数: {info.get('uptime_in_days', '?')} 天")
        print("  [OK] 服务器信息获取正常")
    except Exception as e:
        print(f"  [FAIL] 获取服务器信息失败: {e}")

    print("\n" + "=" * 40)
    print("所有测试完成！Redis 运行正常。")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="测试 Redis 连通性与功能")
    parser.add_argument("--host", default="127.0.0.1", help="Redis 主机地址 (默认 127.0.0.1)")
    parser.add_argument("--port", type=int, default=6379, help="Redis 端口 (默认 6379)")
    parser.add_argument("--db", type=int, default=0, help="Redis 数据库编号 (默认 0)")
    parser.add_argument("--password", default=None, help="Redis 密码 (默认无)")
    args = parser.parse_args()

    test_redis(args.host, args.port, args.db, args.password)
