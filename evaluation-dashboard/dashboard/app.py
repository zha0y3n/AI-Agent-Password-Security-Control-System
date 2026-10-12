"""C 的 Dashboard：读 results/*.csv 展示实验结果。"""
import os
import streamlit as st
import pandas as pd

st.set_page_config(page_title="C 安全评测 Dashboard", layout="wide")
st.title("Agent 授权与凭据安全系统 - C 评测 Dashboard")

# 从本文件位置推导 results 目录
HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "..", "results")


def load(name):
    path = os.path.join(RESULTS, name)
    if not os.path.exists(path):
        return None
    return pd.read_csv(path)


st.caption(f"结果目录：{os.path.abspath(RESULTS)}")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "安全测试", "并发测试", "性能测试", "撤销测试", "提示注入"
])

# ========== Tab 1: 安全测试 ==========
with tab1:
    df = load("security.csv")
    if df is None:
        st.warning("还没有 security.csv，请先运行 scripts/run_security_tests.py")
    else:
        total = len(df)
        passed = int(df["passed"].sum())
        c1, c2, c3 = st.columns(3)
        c1.metric("测试用例数", total)
        c2.metric("通过", passed)
        c3.metric("通过率", f"{passed / total * 100:.1f}%")

        st.subheader("明细")
        st.dataframe(df, use_container_width=True)

        st.subheader("按 category 通过率")
        if "category" in df.columns:
            st.bar_chart(df.groupby("category")["passed"].mean())

        st.subheader("响应耗时")
        if "latency_ms" in df.columns:
            st.bar_chart(df.set_index("case_id")["latency_ms"])

# ========== Tab 2: 并发测试 ==========
with tab2:
    df = load("concurrency.csv")
    if df is None:
        st.info("并发测试尚未接入（等 B 的 Broker 完成后跑）")
    else:
        st.dataframe(df, use_container_width=True)

# ========== Tab 3: 性能测试 ==========
with tab3:
    df = load("performance.csv")
    if df is None:
        st.info("性能测试尚未接入")
    else:
        st.dataframe(df, use_container_width=True)

# ========== Tab 4: 撤销测试 ==========
with tab4:
    df = load("revocation.csv")
    if df is None:
        st.info("撤销测试尚未接入（等 B 的 Broker 完成后跑）")
    else:
        st.dataframe(df, use_container_width=True)

# ========== Tab 5: 提示注入 ==========
with tab5:
    df = load("prompt_injection.csv")
    if df is None:
        st.info("提示注入测试尚未接入")
    else:
        st.dataframe(df, use_container_width=True)
