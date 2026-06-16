# ====== 阶段 1：构建阶段 (环境较胖，包含编译器) ======
FROM python:3.11-slim AS builder

WORKDIR /app

# 安装编译所需的工具和开发库
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    pkg-config \
    make \
    autoconf \
    libtool \
    libcairo2-dev \
    libffi-dev

COPY requirements.txt .

# 将依赖安装到指定的 /install 目录下，而不是系统默认路径
# 这样方便我们下一步精准拷贝
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ====== 阶段 2：运行阶段 (环境极瘦，只有运行时库) ======
FROM python:3.11-slim

WORKDIR /app

# 运行阶段只需要动态链接库，不需要 gcc 和 -dev 包！
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 \
    fonts-noto-cjk \
    && rm -rf /var/lib/apt/lists/*

# 从 builder 阶段，把刚刚安装好的 Python 包原封不动拷贝过来
COPY --from=builder /install /usr/local

# 拷贝项目代码
COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]