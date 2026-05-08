# 🔐 CrypEval — 可证明安全参数评测系统

<p align="center">
  <b>基于 Agentic Workflow 的多原语密码安全交互式分析工具</b><br>
  <sub>FastAPI · Streamlit · OpenAI 兼容接口 · 纯 Python 数学引擎</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/backend-FastAPI-009688?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/frontend-Streamlit-FF4B4B?logo=streamlit" alt="Streamlit">
  <img src="https://img.shields.io/badge/AI-工具调用代理-8A2BE2?logo=openai" alt="AI Agent">
  <img src="https://img.shields.io/badge/license-教育/研究-purple" alt="License">
</p>

---

## 📖 项目概述

**CrypEval** 是一个交互式全栈密码安全参数评测工具，覆盖三大密码范式：

- 🧊 **后量子 / 格密码** — LWE、CKKS/RLWE（基于 BKZ 格归约的 Core-SVP 经典分析）
- 🔑 **经典公钥密码** — RSA（GNFS 数域筛法）、ECC（Pollard's rho + Shor 量子警告）
- 🔓 **对称密码 / 哈希暴力破解** — 5 种哈希算法 × 5 级攻击者硬件配置的穷举时间估算

CrypEval 提供**单点安全评估**和**参数扫描曲线可视化**，并内置 **🤖 智能助手模式**：一个基于 LLM 函数调用（Tool Calling）的对话代理，可直接调用后端 API 进行密码学计算，以自然语言回答用户问题。

---

## ✨ 核心功能

### 🧊 后量子 / 格密码

| 原语 | 困难假设 | 评估方法 | 核心公式 |
|------|---------|---------|---------|
| **LWE** (容错学习) | GapSVP → BDD → uSVP | 根厄米特因子 δ → BKZ 块大小 β → 安全比特 λ | *λ* ≈ 0.292·β |
| **CKKS / RLWE** (同态加密) | Ring-LWE → Ideal-SVP | 典范嵌入 + δ → β → λ 流水线 | *δ* = (Q/σ)<sup>1/N</sup> |

### 🔑 经典公钥密码

| 原语 | 攻击方法 | 安全模型 | 特点 |
|------|---------|---------|------|
| **RSA** (整数分解) | GNFS 数域筛法 | *L<sub>N</sub>(1/3, 1.923)* | 经 NIST/ECRYPT-II 校准，支持 1024–15360 bit |
| **ECC** (椭圆曲线) | Pollard's rho + Shor | 经典 *λ* = k/2 | ⚠️ 量子计算机上安全级别降为 0 bit |

### 🔓 对称密码暴力破解

- 🖥️ **5 级威胁模型** — 从消费级 CPU 到国家级 ASIC 集群
- 🔢 **5 种哈希算法** — MD5、SHA-256、NTLM、WPA2 PBKDF2、Argon2
- 🧠 **Argon2 内存硬化建模** — GPU/ASIC 速率受 VRAM 带宽瓶颈压制（约 10⁷× 慢于 MD5）
- 📊 **破解时间对比表** — 含 emoji 指示符（🔴 < 1 天 / 🟡 < 1 年 / 🟢 > 1 年）

### 📈 动态权衡可视化

- LWE：**晶格维度 n** vs. **安全级别 λ** 曲线
- CKKS：**系数模数 log₂ Q** vs. **安全级别 λ** 曲线
- 交互式 `st.line_chart`，参数变化即时反映

### 🤖 智能助手模式（LLM 工具调用代理）

- 基于 OpenAI 兼容接口的函数调用（Function Calling）
- 自动将用户自然语言问题转换为后端 API 调用
- 以专业中文密码学分析回复用户
- 支持任意兼容接口（SiliconFlow、DeepSeek、OpenAI 等）

---

## 📊 密码学困难假设速览

| 原语 | 困难假设 | 最佳已知攻击 | 经典安全 λ |
|------|---------|-------------|-----------|
| LWE | GapSVP → BDD → uSVP | BKZ 格归约 | 0.292 · β |
| CKKS / RLWE | Ring-LWE → Ideal-SVP | 典范嵌入 BKZ | 0.292 · β |
| RSA | 整数分解 | GNFS 数域筛法 | *L<sub>N</sub>(1/3, 1.923)* |
| ECC | ECDLP | Pollard's rho | *k*/2 |
| 暴力破解 | 密钥空间穷举 | 穷举搜索 | *log₂(S)* |
| Argon2 | 内存硬化 KDF | 内存带宽限制搜索 | *log₂(S / rate)* |

---

## 🏗️ 项目架构

```
CrypEval/
├── backend/                       # FastAPI 后端（密码计算引擎）
│   ├── main.py                    # API 入口，路由分发 (7 个端点)
│   ├── lwe_estimator.py           # LWE: δ → β → λ (Core-SVP)
│   ├── ckks_estimator.py          # CKKS / RLWE 安全估算
│   ├── rsa_estimator.py           # RSA GNFS 复杂度估算
│   ├── ecc_estimator.py           # ECC Pollard's rho + Shor 警告
│   └── bruteforce_estimator.py    # 多对手硬件暴力破解模拟
├── frontend/
│   └── app.py                     # Streamlit UI (控制面板 + 智能助手)
├── requirements.txt               # 依赖声明
├── REPORT_DRAFT.md                # 学术报告（中文）
├── PPT_OUTLINE.md                 # 演示文稿大纲（中文）
└── README.md
```

### 设计原则

- **后端（FastAPI）** — 薄层数学引擎。每个估算器是独立的纯 Python 模块，实现标准密码学硬度公式，不依赖外部密码库（如 SEAL），保持依赖精简且代码可审计。
- **前端（Streamlit）** — 交互式 UI，提供动态滑块、指标卡片、颜色编码安全评级、折线图和可展开困难假设说明。前端**不执行任何密码计算**，所有估算通过 REST API 委托给后端。
- **智能助手** — 基于 OpenAI 兼容接口，将 `evaluate_cryptography` 工具定义注入 LLM，实现自然语言驱动的密码参数分析。

---

## 🚀 快速开始

> 环境要求：Linux 或 WSL，Python 3.10+

### 1️⃣ 克隆仓库

```bash
git clone https://github.com/QinBei798/CrypEval.git
cd CrypEval
```

### 2️⃣ 创建并激活虚拟环境

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3️⃣ 安装依赖

```bash
pip install -r requirements.txt
```

### 4️⃣ 启动 FastAPI 后端（终端 1）

```bash
cd backend
uvicorn main:app --host 127.0.0.1 --port 8000
```

> 交互式 API 文档自动生成于 http://127.0.0.1:8000/docs

### 5️⃣ 启动 Streamlit 前端（终端 2）

```bash
cd frontend
streamlit run app.py
```

> 前端界面自动打开于 http://localhost:8501

### 6️⃣（可选）使用智能助手

1. 切换到 **🤖 智能助手模式** 标签页
2. 在侧边栏展开 **⚙️ 助手模型设置**
3. 填入 API Base URL、API 密钥和模型名称
4. 即可用自然语言咨询密码参数安全性

---

## 📡 API 参考

所有端点均为 `GET` 方法，接受查询参数，返回 JSON。

| 端点 | 参数 | 说明 |
|------|------|------|
| `/evaluate/lwe` | `n`, `q`, `sigma` | LWE 单点安全评估 |
| `/evaluate/lwe/curve` | `q`, `sigma` | 扫描 *n* (256–1024) → [{x, y}] 曲线数据 |
| `/evaluate/ckks` | `N`, `Q`, `sigma` (默认 3.2) | CKKS / RLWE 单点安全评估 |
| `/evaluate/ckks/curve` | `N`, `sigma` | 扫描 *log₂ Q* (10–800) → [{x, y}] 曲线数据 |
| `/evaluate/rsa` | `modulus_bits` | RSA GNFS 安全估算 |
| `/evaluate/ecc` | `curve_bits` | ECC 经典 + 量子安全评估 |
| `/evaluate/bruteforce` | `algo`, `length`, `charset_size` | 多对手暴力破解时间表 |

### 示例请求

```bash
# LWE 估算
curl "http://127.0.0.1:8000/evaluate/lwe?n=1024&q=4294967296&sigma=3.2"

# RSA 估算
curl "http://127.0.0.1:8000/evaluate/rsa?modulus_bits=2048"

# 暴力破解估算
curl "http://127.0.0.1:8000/evaluate/bruteforce?algo=Argon2%20(Memory-Hard%2C%20Modern%20Standard)&length=8&charset_size=62"
```

---

## 🤖 Agentic Workflow 开发流程

本项目完全采用 **Agentic Workflow（Claude Code）** 开发，共 10 个阶段：

```
脚手架 → LWE 核心引擎 → Streamlit UI → 多原语扩展 → ECC
→ 参数权衡可视化 → 暴力破解模拟 → 学术报告/PPT → 工具调用代理 → 全中文化
```

---

## 📄 许可说明

本项目仅供教育和研究用途。在实际部署密码参数之前，请务必参考当前最新的密码学标准（NIST、ECRYPT、BSI、国密）。

---

<p align="center">
  <sub>Built with ❤️ using Claude Code Agentic Workflow · 2026</sub>
</p>
