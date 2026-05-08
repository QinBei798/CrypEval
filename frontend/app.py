import streamlit as st
import requests
import json
from openai import OpenAI

BACKEND_BASE = "http://127.0.0.1:8000"

# ---- Display label mappings (internal value → Chinese display) ----
PRIMITIVE_OPTIONS = [
    "LWE (Learning With Errors)",
    "CKKS / RLWE (Homomorphic Encryption)",
    "RSA (Factoring)",
    "ECC (Elliptic Curve / SECP256K1)",
    "Symmetric & Hash Brute-force",
]
PRIMITIVE_LABELS = {
    "LWE (Learning With Errors)": "LWE (容错学习)",
    "CKKS / RLWE (Homomorphic Encryption)": "CKKS / RLWE (同态加密)",
    "RSA (Factoring)": "RSA (整数分解)",
    "ECC (Elliptic Curve / SECP256K1)": "ECC (椭圆曲线 / SECP256K1)",
    "Symmetric & Hash Brute-force": "对称密码与哈希暴力破解",
}

ALGO_OPTIONS = [
    "MD5 (Fast Hash)",
    "SHA-256 (Fast, ASIC-dominated)",
    "NTLM (Extremely Fast, Windows AD)",
    "WPA2 PBKDF2 (Slow Hash)",
    "Argon2 (Memory-Hard, Modern Standard)",
]
ALGO_LABELS = {
    "MD5 (Fast Hash)": "MD5 (快速哈希)",
    "SHA-256 (Fast, ASIC-dominated)": "SHA-256 (快速，ASIC 占优)",
    "NTLM (Extremely Fast, Windows AD)": "NTLM (极速，Windows AD)",
    "WPA2 PBKDF2 (Slow Hash)": "WPA2 PBKDF2 (慢速哈希)",
    "Argon2 (Memory-Hard, Modern Standard)": "Argon2 (内存硬化，现代标准)",
}

CHARSET_OPTIONS = ["Digits (10)", "Hexadecimal (16)", "Alphanumeric (62)", "Full ASCII (95)"]
CHARSET_LABELS = {
    "Digits (10)": "纯数字 (10)",
    "Hexadecimal (16)": "十六进制 (16)",
    "Alphanumeric (62)": "字母数字 (62)",
    "Full ASCII (95)": "全 ASCII (95)",
}

ASSESSMENT_CN = {
    "Insecure": "不安全",
    "Weak": "较弱",
    "Acceptable": "可接受",
    "Strong": "高强度",
    "Secure": "安全",
}


# ---- Tool Schema for LLM Function Calling ----
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "evaluate_cryptography",
            "description": (
                "评估给定密码原语参数的安全级别（以比特为单位）。"
                "返回估算的安全比特数、根厄米特因子、BKZ 块大小以及安全评估结论。"
                "每当用户询问密码参数安全性或想要评估某组参数的安全强度时，请使用此工具。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "primitive": {
                        "type": "string",
                        "enum": ["LWE", "CKKS", "RSA", "ECC", "Bruteforce"],
                        "description": "要评估的密码原语类型"
                    },
                    "parameters": {
                        "type": "object",
                        "description": (
                            "各原语所需的参数。"
                            "LWE: n (int, 256-2048), q (int), sigma (float, ~3.2)。"
                            "CKKS: N (int, 1024-32768), Q (int), sigma (float, ~3.2)。"
                            "RSA: modulus_bits (int, 如 2048)。"
                            "ECC: curve_bits (int, 如 256)。"
                            "Bruteforce: algo (str，可选值: 'MD5 (Fast Hash)', "
                            "'SHA-256 (Fast, ASIC-dominated)', "
                            "'NTLM (Extremely Fast, Windows AD)', "
                            "'WPA2 PBKDF2 (Slow Hash)', "
                            "'Argon2 (Memory-Hard, Modern Standard)')，"
                            "length (int, 密码长度), charset_size (int, 如 62 表示字母数字)。"
                        )
                    }
                },
                "required": ["primitive", "parameters"]
            }
        }
    }
]

SYSTEM_PROMPT = (
    "你是集成在 CrypEval（可证明安全参数评测系统）中的密码学专家助手。"
    "你的职责是帮助用户理解密码参数选择对安全性的影响。\n\n"
    "规则:\n"
    "- 始终使用 evaluate_cryptography 工具获取实际的数值估算结果。"
    "绝不猜测或编造安全级别。\n"
    "- 收到工具返回的结果后，用通俗易懂的语言进行解释。"
    "明确指出该参数是否适合实际部署。\n"
    "- 对于 ECC，务必警告 Shor 算法会将量子安全性降为 0 比特。\n"
    "- 对于暴力破解，根据用户的威胁模型解释应关注哪个硬件配置。\n"
    "- 简洁但全面。使用项目符号进行比较。"
    "- 请用中文回复用户。"
)


def execute_crypto_tool(primitive: str, params: dict) -> dict:
    """调用 FastAPI 后端执行密码学评估。"""
    endpoint_map = {
        "LWE": "/evaluate/lwe",
        "CKKS": "/evaluate/ckks",
        "RSA": "/evaluate/rsa",
        "ECC": "/evaluate/ecc",
        "Bruteforce": "/evaluate/bruteforce",
    }
    endpoint = endpoint_map.get(primitive)
    if not endpoint:
        return {"error": f"未知原语: {primitive}"}

    resp = requests.get(f"{BACKEND_BASE}{endpoint}", params=params, timeout=15)
    resp.raise_for_status()
    return resp.json()


st.set_page_config(page_title="CrypEval: 可证明安全参数评测系统", layout="wide")
st.title("CrypEval: 可证明安全参数评测系统")

# ---- Sidebar ----
with st.sidebar:
    st.header("参数配置")

    # --- LLM Settings ---
    with st.expander("⚙️ 助手模型设置"):
        api_base = st.text_input(
            "API Base URL",
            value="https://api.siliconflow.cn/v1",
            help="兼容 OpenAI 接口的 API 端点"
        )
        api_key = st.text_input(
            "API 密钥",
            type="password",
            help="LLM 服务的 API 密钥"
        )
        model_name = st.text_input(
            "模型名称",
            value="deepseek-ai/DeepSeek-V3",
            help="模型标识符 (兼容 OpenAI 接口)"
        )

    st.divider()

    primitive = st.selectbox(
        "选择加密原语",
        options=PRIMITIVE_OPTIONS,
        format_func=lambda x: PRIMITIVE_LABELS[x],
    )

    st.divider()

    # Dynamic sliders based on primitive
    if primitive == "LWE (Learning With Errors)":
        st.subheader("LWE 参数")
        n = st.slider("晶格维度 $n$",
                      min_value=256, max_value=2048, step=256, value=512)
        log2_q = st.slider("模数 $\\log_2 q$",
                           min_value=10, max_value=60, step=1, value=32)
        sigma = st.slider("噪声标准差 $\\sigma$",
                          min_value=1.0, max_value=8.0, step=0.1, value=3.2)
        endpoint = "/evaluate/lwe"
        params_fn = lambda: {"n": n, "q": 2 ** log2_q, "sigma": sigma}
        extra_context = {"log2_q": log2_q}

    elif primitive == "CKKS / RLWE (Homomorphic Encryption)":
        st.subheader("CKKS / RLWE 参数")
        N = st.slider("环维度 $N$",
                      min_value=1024, max_value=32768, step=1024, value=4096)
        log2_Q = st.slider("系数模数 $\\log_2 Q$",
                           min_value=100, max_value=3000, step=50, value=200)
        sigma = st.slider("噪声标准差 $\\sigma$",
                          min_value=1.0, max_value=8.0, step=0.1, value=3.2)
        endpoint = "/evaluate/ckks"
        params_fn = lambda: {"N": N, "Q": 2 ** log2_Q, "sigma": sigma}
        extra_context = {"log2_Q": log2_Q, "N": N}

    elif primitive == "ECC (Elliptic Curve / SECP256K1)":
        st.subheader("ECC 参数")
        curve_bits = st.select_slider(
            "曲线大小 (bits)",
            options=[160, 224, 256, 384, 521],
            value=256,
        )
        endpoint = "/evaluate/ecc"
        params_fn = lambda: {"curve_bits": curve_bits}
        extra_context = {}

    elif primitive == "Symmetric & Hash Brute-force":
        st.subheader("暴力破解参数")
        algo = st.selectbox(
            "算法选择",
            options=ALGO_OPTIONS,
            format_func=lambda x: ALGO_LABELS[x],
        )
        length = st.slider("密码长度",
                           min_value=6, max_value=20, value=8)
        charset_name = st.selectbox(
            "字符集",
            options=CHARSET_OPTIONS,
            format_func=lambda x: CHARSET_LABELS[x],
        )
        charset_map = {"Digits (10)": 10, "Hexadecimal (16)": 16,
                       "Alphanumeric (62)": 62, "Full ASCII (95)": 95}
        charset_size = charset_map[charset_name]
        endpoint = "/evaluate/bruteforce"
        params_fn = lambda: {"algo": algo, "length": length, "charset_size": charset_size}
        extra_context = {"charset_name": charset_name}

    else:  # RSA
        st.subheader("RSA 参数")
        modulus_bits = st.select_slider(
            "模数位数 (bits)",
            options=[1024, 2048, 3072, 4096, 6144, 7680, 8192, 15360],
            value=2048,
        )
        endpoint = "/evaluate/rsa"
        params_fn = lambda: {"modulus_bits": modulus_bits}
        extra_context = {}

    st.divider()
    evaluate = st.button("评估安全性", type="primary", use_container_width=True)


# ---- Tabs ----
tab_dashboard, tab_agent = st.tabs(["📊 控制面板模式", "🤖 智能助手模式"])

# ============================================================
# TAB 1: 控制面板模式 (原有功能)
# ============================================================
with tab_dashboard:
    if evaluate:
        params = params_fn()
        backend_error = False

        with st.spinner("正在估算安全级别..."):
            try:
                resp = requests.get(f"{BACKEND_BASE}{endpoint}", params=params, timeout=10)
                resp.raise_for_status()
                data = resp.json()
            except requests.ConnectionError:
                st.error(f"无法连接到后端 {BACKEND_BASE}")
                st.info("请在后端目录启动服务: `cd backend && uvicorn main:app --host 127.0.0.1 --port 8000`")
                backend_error = True
            except Exception as e:
                st.error(f"后端错误: {e}")
                backend_error = True

        if not backend_error:
            # ---- 暴力破解展示 (特殊处理) ----
            if primitive == "Symmetric & Hash Brute-force":
                st.subheader("搜索空间")
                st.metric(label="密钥空间总量",
                          value=data["search_space_display"],
                          help=f"{data['charset_size']}^{data['length']} = {data['search_space']:.2e}")

                st.subheader("多对手暴力破解对比")
                rows = []
                for r in data["results"]:
                    rows.append({
                        "威胁主体 (硬件)": r["actor"],
                        "算力": r["hash_rate"],
                        "理论破解用时": f"{r['indicator']} {r['time_display']}",
                    })
                st.dataframe(rows, use_container_width=True, hide_index=True)

                st.caption("\U0001f534 < 1 天  |  \U0001f7e1 < 1 年  |  \U0001f7e2 > 1 年  |  无法破解 > 10⁵ 年")

                with st.expander("暴力破解攻击模型与假设", expanded=False):
                    st.markdown(f"""
                    **攻击模型:** 对整个密钥空间进行穷举搜索（暴力破解）。

                    **假设条件:**
                    - 攻击者已获取密码哈希值，可以在离线环境中测试猜测结果。
                    - 除算法本身的成本外，未施加额外的加盐 / 密钥拉伸措施。
                    - 硬件哈希率均为近似值，代表持续吞吐量。

                    **算法:** {data["algo"]} ({data["algo_family"]} 哈希族)
                    **密码长度:** {data["length"]} 字符
                    **字符集:** {extra_context["charset_name"]} ({data["charset_size"]} 种符号)
                    **密钥空间总量:** {data["search_space"]:.2e} 种可能

                    ---
                    破解时间按 $T = \\frac{{\\text{{密钥空间}}}}{{\\text{{哈希速率}}}}$
                    对每种硬件配置分别计算。实际攻击可能因字典攻击、彩虹表或 ASIC 优化而更快。
                    建议使用强加盐密钥派生函数（如 Argon2、bcrypt）来抵御暴力破解威胁。
                    """)

            else:
                # ---- 指标卡片（非暴力破解原语） ----
                lam = data["security_level_bits"]
                assessment = data["assessment"]
                assessment_display = ASSESSMENT_CN.get(assessment, assessment)

                if primitive == "ECC (Elliptic Curve / SECP256K1)":
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric(label="经典安全级别 $\\lambda$", value=f"{lam} bits",
                                  delta=assessment_display,
                                  delta_color="normal" if lam >= 112 else "inverse")
                    with col2:
                        st.metric(label="曲线大小",
                                  value=f"{data['curve_bits']}-bit")
                    with col3:
                        st.metric(label="量子安全级别",
                                  value="0 bits", delta="被 Shor 算法攻破",
                                  delta_color="inverse")
                elif primitive != "RSA (Factoring)":
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric(label="安全级别 $\\lambda$", value=f"{lam} bits",
                                  delta=assessment_display,
                                  delta_color="normal" if lam >= 112 else "inverse")
                    with col2:
                        st.metric(label="根厄米特因子 $\\delta$",
                                  value=f"{data['root_hermite_factor']:.6f}")
                    with col3:
                        st.metric(label="BKZ 块大小 $\\beta$",
                                  value=f"{data['estimated_bkz_block_size']:.0f}")
                else:
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric(label="安全级别 $\\lambda$", value=f"{lam} bits",
                                  delta=assessment_display,
                                  delta_color="normal" if lam >= 112 else "inverse")
                    with col2:
                        st.metric(label="RSA 模数位数",
                                  value=f"{data['modulus_bits']}-bit")
                    with col3:
                        st.metric(label="GNFS $\\log_2$ 成本",
                                  value=f"{data['gnfs_log2_cost']}")

                # ---- 颜色编码安全评级 ----
                if primitive == "ECC (Elliptic Curve / SECP256K1)":
                    st.warning(
                        ":warning: **量子漏洞警告:** Shor 算法可以在容错量子计算机上以"
                        "多项式时间求解椭圆曲线离散对数问题 (ECDLP)，使 ECC 的安全性"
                        "降为实质上的 **0 比特**。ECC 不提供后量子安全性。"
                        "上述经典安全估算假设攻击者不拥有大规模量子计算机。"
                    )

                if lam < 80:
                    st.error(f"安全级别 $\\lambda = {lam}$ bits 属于 **不安全** (低于 80-bit 标准)。")
                elif lam < 112:
                    st.warning(f"安全级别 $\\lambda = {lam}$ bits 属于 **较弱** (低于 112-bit 标准)。")
                elif lam < 128:
                    st.info(f"安全级别 $\\lambda = {lam}$ bits 属于 **可接受** (接近 128-bit 标准)。")
                else:
                    st.success(f"安全级别 $\\lambda = {lam}$ bits 属于 **高强度** (达到 128-bit 及以上标准)。")

                # ---- 可证明安全说明 ----
                with st.expander("可证明安全与困难假设", expanded=False):
                    st.markdown(f"""
                    **困难假设:** {data["hardness_assumption"]}

                    {data["explanation"]}
                    """)

                    if primitive == "LWE (Learning With Errors)":
                        st.markdown(f"""
                        ---
                        **使用参数:**
                        - $n = {data["n"]}$ (晶格维度)
                        - $q = {data["q"]}$ (模数，$\\log_2 q = {extra_context["log2_q"]}$)
                        - $\\sigma = {data["sigma"]}$ (噪声标准差)
                        """)
                    elif primitive == "CKKS / RLWE (Homomorphic Encryption)":
                        st.markdown(f"""
                        ---
                        **使用参数:**
                        - $N = {data["N"]}$ (环维度)
                        - $Q = {data["Q"]}$ (系数模数，$\\log_2 Q = {extra_context["log2_Q"]}$)
                        - $\\sigma = {data["sigma"]}$ (噪声标准差)
                        """)
                    elif primitive == "ECC (Elliptic Curve / SECP256K1)":
                        st.markdown(f"""
                        ---
                        **使用参数:**
                        - 曲线大小: {data["curve_bits"]} bits
                        - 经典攻击: Pollard's rho — $O(2^{{{data['classical_security_bits']}}})$
                        - 量子攻击: Shor 算法 — 多项式时间
                        """)
                    else:
                        st.markdown(f"""
                        ---
                        **使用参数:**
                        - RSA 模数位数: {data["modulus_bits"]} bits
                        """)

                # ---- 参数权衡分析 (仅 LWE 和 CKKS) ----
                if primitive in ("LWE (Learning With Errors)", "CKKS / RLWE (Homomorphic Encryption)"):
                    st.divider()
                    st.subheader("安全性权衡分析")

                    if primitive == "LWE (Learning With Errors)":
                        x_label = "晶格维度 $n$"
                        curve_endpoint = "/evaluate/lwe/curve"
                        curve_params = {"q": 2 ** log2_q, "sigma": sigma}
                        explanation = (
                            "在固定模数 $q$ 和噪声水平 $\\sigma$ 的条件下，增加晶格维度 $n$ "
                            "可以指数级提升安全性。每增加 64 维，根厄米特因子便会更趋近于 1，"
                            "迫使攻击者使用更大的 BKZ 块大小才能攻破方案。"
                        )
                    else:
                        x_label = "系数模数 $\\log_2 Q$"
                        curve_endpoint = "/evaluate/ckks/curve"
                        curve_params = {"N": N, "sigma": sigma}
                        explanation = (
                            "在固定环维度 $N$ 的条件下，增大系数模数 $Q$ 会显著降低"
                            "安全比特数 $\\lambda$。这是因为 $Q$ 越大意味着 $Q/\\sigma$ "
                            "比值越大，从而使根厄米特因子 $\\delta$ 偏离 1.0，BKZ 攻击"
                            "变得更容易。"
                        )

                    with st.spinner("正在生成权衡曲线..."):
                        try:
                            curve_resp = requests.get(
                                f"{BACKEND_BASE}{curve_endpoint}", params=curve_params, timeout=30
                            )
                            curve_resp.raise_for_status()
                            curve_data = curve_resp.json()
                        except Exception:
                            st.warning("无法加载权衡曲线数据。")
                            curve_data = None

                    if curve_data:
                        chart_df = {"x": [p["x"] for p in curve_data],
                                    "y": [p["y"] for p in curve_data]}
                        st.line_chart(chart_df, x="x", y="y", x_label=x_label,
                                      y_label="安全级别 $\\lambda$ (bits)")
                        st.caption(explanation)

    else:
        st.info("请在侧边栏中选择加密原语、调整参数，然后点击 **评估安全性**。")


# ============================================================
# TAB 2: 智能助手模式
# ============================================================
with tab_agent:
    # Initialize chat history
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Display chat history
    for msg in st.session_state.messages:
        role = msg["role"]
        if role == "user":
            with st.chat_message("user"):
                st.markdown(msg["content"])
        elif role == "assistant" and msg.get("content") and not msg.get("tool_calls"):
            with st.chat_message("assistant"):
                st.markdown(msg["content"])
        elif role == "assistant" and msg.get("tool_calls"):
            with st.chat_message("assistant"):
                for tc in msg["tool_calls"]:
                    fn_name = tc["function"]["name"]
                    try:
                        fn_args = json.dumps(json.loads(tc["function"]["arguments"]), indent=2)
                    except Exception:
                        fn_args = tc["function"]["arguments"]
                    st.info(f"🔧 **调用 `{fn_name}`**\n\n```json\n{fn_args}\n```")
        elif role == "tool":
            with st.expander(
                f"📋 工具返回结果 ({msg.get('primitive', 'crypto')})", expanded=False
            ):
                try:
                    result_data = json.loads(msg["content"])
                    st.json(result_data)
                except Exception:
                    st.text(msg["content"])

    # Show welcome prompt if chat is empty
    if not st.session_state.messages:
        st.info(
            "向密码学助手咨询任何关于参数安全性的问题。示例:\n\n"
            "- *\"RSA-2048 在经典攻击者面前是否仍然安全？\"*\n"
            "- *\"256-bit ECC 曲线能提供多少安全级别？\"*\n"
            "- *\"请估算 LWE 参数 n=1024, q=2^32, sigma=3.2 的安全级别\"*\n"
            "- *\"使用 Argon2 暴力破解 8 位字母数字密码需要多长时间？\"*\n"
            "- *\"请对比 N=4096 和 N=8192 时 CKKS 在 log2 Q=200 下的安全性\"*"
        )

    # Chat input
    if prompt := st.chat_input("咨询关于密码参数安全性的问题..."):
        # Add and display user message
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Validate API key
        if not api_key or api_key.strip() == "":
            with st.chat_message("assistant"):
                st.error(
                    "⚠️ 请在侧边栏 (⚙️ 助手模型设置) 中配置 **API 密钥** 以启用智能助手。"
                )
            st.stop()

        # Build LLM client
        client = OpenAI(base_url=api_base, api_key=api_key)

        # Build message list for LLM (convert session state to OpenAI format)
        def build_llm_messages():
            msgs = [{"role": "system", "content": SYSTEM_PROMPT}]
            for m in st.session_state.messages:
                if m["role"] == "tool":
                    msgs.append({
                        "role": "tool",
                        "tool_call_id": m["tool_call_id"],
                        "content": m["content"]
                    })
                elif m["role"] == "assistant" and m.get("tool_calls"):
                    msgs.append({
                        "role": "assistant",
                        "content": m.get("content"),
                        "tool_calls": m["tool_calls"]
                    })
                else:
                    msgs.append({"role": m["role"], "content": m.get("content", "")})
            return msgs

        # First LLM call (with tools)
        try:
            with st.spinner("思考中..."):
                response = client.chat.completions.create(
                    model=model_name,
                    messages=build_llm_messages(),
                    tools=TOOLS,
                    tool_choice="auto",
                )
        except Exception as e:
            with st.chat_message("assistant"):
                st.error(f"❌ 大模型 API 错误: {e}")
            st.stop()

        assistant_msg = response.choices[0].message

        # Handle tool calls
        if assistant_msg.tool_calls:
            # Store assistant tool-call message in session state
            tc_dicts = []
            for tc in assistant_msg.tool_calls:
                tc_dicts.append({
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    }
                })

            st.session_state.messages.append({
                "role": "assistant",
                "content": assistant_msg.content,
                "tool_calls": tc_dicts,
            })

            # Display tool calls
            with st.chat_message("assistant"):
                for tc in assistant_msg.tool_calls:
                    try:
                        fn_args = json.dumps(json.loads(tc.function.arguments), indent=2)
                    except Exception:
                        fn_args = tc.function.arguments
                    st.info(f"🔧 **调用 `{tc.function.name}`**\n\n```json\n{fn_args}\n```")

            # Execute each tool call against FastAPI backend
            for tc in assistant_msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                    prim = args["primitive"]
                    params = args["parameters"]
                    result = execute_crypto_tool(prim, params)
                except requests.ConnectionError:
                    result = {
                        "error": f"无法连接到后端 {BACKEND_BASE}。请先启动 FastAPI 服务。"
                    }
                except Exception as e:
                    result = {"error": str(e)}

                # Store tool result in session state
                st.session_state.messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result),
                    "primitive": args.get("primitive", "unknown"),
                })

                # Display tool result
                with st.expander(
                    f"📋 工具返回结果: `{tc.function.name}` ({args.get('primitive', '?')})",
                    expanded=False
                ):
                    st.json(result)

            # Second LLM call (with tool results, without tools)
            with st.spinner("正在生成分析..."):
                try:
                    response2 = client.chat.completions.create(
                        model=model_name,
                        messages=build_llm_messages(),
                    )
                except Exception as e:
                    with st.chat_message("assistant"):
                        st.error(f"❌ 大模型 API 最终响应错误: {e}")
                    st.stop()

            final_msg = response2.choices[0].message

            if final_msg.content:
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": final_msg.content
                })
                with st.chat_message("assistant"):
                    st.markdown(final_msg.content)

        else:
            # No tool call — direct text response
            if assistant_msg.content:
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": assistant_msg.content
                })
                with st.chat_message("assistant"):
                    st.markdown(assistant_msg.content)
            else:
                with st.chat_message("assistant"):
                    st.warning("模型返回了空响应，请尝试重新表述您的问题。")
