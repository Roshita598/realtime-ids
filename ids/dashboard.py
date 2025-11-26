import streamlit as st
import sqlite3
import pandas as pd
import os

DB = os.path.join(os.path.dirname(__file__), "..", "alerts.db")

st.set_page_config(page_title="IDS Dashboard", layout="wide")

st.title("🔐 Real-Time IDS Dashboard")

def get_data():
    conn = sqlite3.connect(DB)
    df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 50", conn)
    conn.close()
    return df

placeholder = st.empty()

while True:
    df = get_data()
    with placeholder.container():
        st.subheader("Recent Alerts")
        st.dataframe(df)

        st.subheader("Count by Type")
        if len(df) > 0:
            st.bar_chart(df["alert_type"].value_counts())

    st.sleep(2)