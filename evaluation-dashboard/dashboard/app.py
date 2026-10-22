"""C 的最终 Dashboard：读取 7 个实验结果并展示（带颜色美化版）。"""
import os
import streamlit as st
import pandas as pd

st.set_page_config(page_title="C 安全评测 Dashboard", layout="wide")
st.title("Agent 授权与凭据安全系统 - C 评测 Dashboard")

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "..", "results")

def load(name):
    path = os.path.join(RESULTS, name)
    if not os.path.exists(path):
        return None
    df = pd.read_csv(path)
    # 美化：把 True/False 变成直观的文字
    if "passed" in df.columns:
        df["passed"] = df["passed"].apply(lambda x: "✅ PASS" if x else "❌ FAIL")
    if "safe" in df.columns:
        df["safe"] = df["safe"].apply(lambda x: "✅ SAFE" if x else "❌ UNSAFE")
    return df

st.caption(f"结果目录：{os.path.abspath(RESULTS)}")

tabs = st.tabs([
    "issue 测试", "verify 测试", "凭据生命周期", 
    "并发测试", "性能测试", "撤销竞态", "提示注入"
])

# 1. issue 测试
with tabs[0]:
    df = load("security.csv")
    if df is None: st.warning("缺少 security.csv")
    else:
        total = len(df)
        # 统计通过数时需要把文字转换回布尔值，或者直接重新读原文件
        raw_df = pd.read_csv(os.path.join(RESULTS, "security.csv"))
        passed = int(raw_df["passed"].sum())
        st.metric("通过率", f"{passed}/{total} ({(passed/total)*100:.1f}%)")
        st.dataframe(df, use_container_width=True)

# 2. verify 测试
with tabs[1]:
    df = load("verify.csv")
    if df is None: st.warning("缺少 verify.csv")
    else:
        raw_df = pd.read_csv(os.path.join(RESULTS, "verify.csv"))
        total, passed = len(df), int(raw_df["passed"].sum())
        st.metric("通过率", f"{passed}/{total} ({(passed/total)*100:.1f}%)")
        st.dataframe(df, use_container_width=True)

# 3. 凭据生命周期
with tabs[2]:
    df = load("credential_lifecycle.csv")
    if df is None: st.warning("缺少 credential_lifecycle.csv")
    else:
        raw_df = pd.read_csv(os.path.join(RESULTS, "credential_lifecycle.csv"))
        total, passed = len(df), int(raw_df["passed"].sum())
        st.metric("通过率", f"{passed}/{total} ({(passed/total)*100:.1f}%)")
        st.dataframe(df, use_container_width=True)

# 4. 并发测试
with tabs[3]:
    df = load("concurrency.csv")
    if df is None: st.warning("缺少 concurrency.csv")
    else:
        raw_df = pd.read_csv(os.path.join(RESULTS, "concurrency.csv"))
        st.metric("最大并发副作用次数", int(raw_df["side_effect_count"].max()), 
                  help="无论多少并发，真实副作用最多只能是 1 次")
        st.dataframe(df, use_container_width=True)
        st.bar_chart(raw_df.groupby("concurrency")["side_effect_count"].mean())

# 5. 性能测试
with tabs[4]:
    df = load("performance.csv")
    if df is None: st.warning("缺少 performance.csv")
    else:
        st.subheader("吞吐量 (RPS)")
        st.line_chart(df.groupby("concurrency")["throughput_rps"].mean())
        st.subheader("延迟分位 (P50 / P95 / P99)")
        st.line_chart(df.groupby("concurrency")[["p50_ms", "p95_ms", "p99_ms"]].mean())
        st.dataframe(df, use_container_width=True)

# 6. 撤销竞态
with tabs[5]:
    df = load("revocation.csv")
    if df is None: st.warning("缺少 revocation.csv")
    else:
        raw_df = pd.read_csv(os.path.join(RESULTS, "revocation.csv"))
        safe_count = int(raw_df["safe"].sum())
        st.metric("竞态安全次数", f"{safe_count}/{len(df)}")
        st.dataframe(df, use_container_width=True)

# 7. 提示注入
with tabs[6]:
    df = load("prompt_injection.csv")
    if df is None: st.warning("缺少 prompt_injection.csv")
    else:
        raw_df = pd.read_csv(os.path.join(RESULTS, "prompt_injection.csv"))
        total, passed = len(df), int(raw_df["passed"].sum())
        st.metric("拦截成功率", f"{passed}/{total} ({(passed/total)*100:.1f}%)")
        st.dataframe(df, use_container_width=True)

with tab7:
    df = load("broker_full_attack.csv")
    if df is None: st.info("Broker全链路测试尚未接入")
    else:
        total = len(df); passed = int(df["passed"].sum())
        c1, c2, c3 = st.columns(3)
        c1.metric("用例数", total)
        c2.metric("通过", passed)
        c3.metric("通过率", f"{passed / total * 100:.1f}%")
        st.dataframe(df, use_container_width=True)
