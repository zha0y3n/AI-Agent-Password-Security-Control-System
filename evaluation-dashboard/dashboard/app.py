"""Dashboard：读取 8 个实验结果并展示"""
import os
import streamlit as st
import pandas as pd

st.set_page_config(page_title="C 安全评测 Dashboard", layout="wide")
st.title("Agent 授权与凭据安全系统 - C 评测 Dashboard")

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "..", "results")

# 核心修复：从原始 CSV 读取用于计算的 df，从美化后的 df 读取用于展示的 df
def load_raw(name):
    path = os.path.join(RESULTS, name)
    if not os.path.exists(path):
        return None
    return pd.read_csv(path)

def load_display(df):
    if df is None:
        return None
    df_disp = df.copy()
    if "passed" in df_disp.columns:
        df_disp["passed"] = df_disp["passed"].apply(lambda x: "✅ PASS" if bool(x) else "❌ FAIL")
    if "safe" in df_disp.columns:
        df_disp["safe"] = df_disp["safe"].apply(lambda x: "✅ SAFE" if bool(x) else "❌ UNSAFE")
    return df_disp

st.caption(f"结果目录：{os.path.abspath(RESULTS)}")

# 核心修复：严格定义 8 个 Tab
tabs = st.tabs([
    "issue 测试", "verify 测试", "凭据生命周期", 
    "并发测试", "性能测试", "撤销竞态", "提示注入", "Broker全链路"
])

# 1. issue 测试
with tabs[0]:
    raw_df = load_raw("security.csv")
    if raw_df is None: st.warning("缺少 security.csv")
    else:
        total, passed = len(raw_df), int(raw_df["passed"].sum())
        st.metric("通过率", f"{passed}/{total} ({(passed/total)*100:.1f}%)")
        st.dataframe(load_display(raw_df), width='stretch')

# 2. verify 测试
with tabs[1]:
    raw_df = load_raw("verify.csv")
    if raw_df is None: st.warning("缺少 verify.csv")
    else:
        total, passed = len(raw_df), int(raw_df["passed"].sum())
        st.metric("通过率", f"{passed}/{total} ({(passed/total)*100:.1f}%)")
        st.dataframe(load_display(raw_df), width='stretch')

# 3. 凭据生命周期
with tabs[2]:
    raw_df = load_raw("credential_lifecycle.csv")
    if raw_df is None: st.warning("缺少 credential_lifecycle.csv")
    else:
        total, passed = len(raw_df), int(raw_df["passed"].sum())
        st.metric("通过率", f"{passed}/{total} ({(passed/total)*100:.1f}%)")
        st.dataframe(load_display(raw_df), width='stretch')

# 4. 并发测试
with tabs[3]:
    raw_df = load_raw("concurrency.csv")
    if raw_df is None: st.warning("缺少 concurrency.csv")
    else:
        st.metric("最大并发副作用次数", int(raw_df["side_effect_count"].max()), 
                  help="无论多少并发，真实副作用最多只能是 1 次")
        st.dataframe(load_display(raw_df), width='stretch')
        st.bar_chart(raw_df.groupby("concurrency")["side_effect_count"].mean())

# 5. 性能测试
with tabs[4]:
    raw_df = load_raw("performance.csv")
    if raw_df is None: st.warning("缺少 performance.csv")
    else:
        st.subheader("吞吐量 (RPS)")
        st.line_chart(raw_df.groupby("concurrency")["throughput_rps"].mean())
        st.subheader("延迟分位 (P50 / P95 / P99)")
        st.line_chart(raw_df.groupby("concurrency")[["p50_ms", "p95_ms", "p99_ms"]].mean())
        st.dataframe(load_display(raw_df), width='stretch')

# 6. 撤销竞态
with tabs[5]:
    raw_df = load_raw("revocation.csv")
    if raw_df is None: st.warning("缺少 revocation.csv")
    else:
        safe_count = int(raw_df["safe"].sum())
        st.metric("竞态安全次数", f"{safe_count}/{len(raw_df)}")
        st.dataframe(load_display(raw_df), width='stretch')

# 7. 提示注入
with tabs[6]:
    raw_df = load_raw("prompt_injection.csv")
    if raw_df is None: st.warning("缺少 prompt_injection.csv")
    else:
        total, passed = len(raw_df), int(raw_df["passed"].sum())
        st.metric("拦截成功率", f"{passed}/{total} ({(passed/total)*100:.1f}%)")
        st.dataframe(load_display(raw_df), width='stretch')

# 8. Broker全链路
with tabs[7]:
    raw_df = load_raw("broker_full_attack.csv")
    if raw_df is None: 
        st.info("Broker全链路测试尚未接入")
    else:
        total, passed = len(raw_df), int(raw_df["passed"].sum())
        c1, c2, c3 = st.columns(3)
        c1.metric("用例数", total)
        c2.metric("通过", passed)
        c3.metric("通过率", f"{passed / total * 100:.1f}%")
        st.dataframe(load_display(raw_df), width='stretch')