import streamlit as st
import numpy as np
import pickle

# Load model
with open("random_forest_model.pkl", "rb") as model_file:
    model = pickle.load(model_file)

# Load label mappings
with open("attack_types.pkl", "rb") as label_file:
    attack_types = pickle.load(label_file)

st.set_page_config(page_title="Network Attack Detector", layout="wide")
st.markdown("<h2 style='text-align: center;'>🔐 Network Traffic Attack Detection</h2>", unsafe_allow_html=True)
st.write("Fill in the following network traffic features to predict potential attack types:")

with st.form("attack_form"):
    # First row
    col1, col2, col3 = st.columns(3)
    with col1:
        dest_port = st.number_input("Destination Port", 0, 65535, 80)
    with col2:
        flow_duration = st.number_input("Flow Duration (μs)", 0, 10_000_000, 1_000_000)
    with col3:
        total_fwd = st.number_input("Fwd Packets", 0, 100_000, 10)

    # Second row
    col4, col5, col6 = st.columns(3)
    with col4:
        total_bwd = st.number_input("Bwd Packets", 0, 100_000, 10)
    with col5:
        fwd_len_total = st.number_input("Fwd Total Len", 0, 1_000_000, 1000)
    with col6:
        bwd_len_total = st.number_input("Bwd Total Len", 0, 1_000_000, 1000)

    # Third row
    col7, col8, col9 = st.columns(3)
    with col7:
        fwd_len_max = st.number_input("Fwd Len Max", 0, 2000, 1500)
    with col8:
        bwd_len_max = st.number_input("Bwd Len Max", 0, 2000, 1500)
    with col9:
        flow_bps = st.number_input("Flow Bytes/sec", value=100_000.0)

    # Fourth row
    col10, col11, col12 = st.columns(3)
    with col10:
        flow_pps = st.number_input("Flow Packets/sec", value=10.0)
    with col11:
        pkt_len_mean = st.number_input("Pkt Len Mean", value=500.0)
    with col12:
        pkt_len_std = st.number_input("Pkt Len Std", value=100.0)

    # Fifth row: Flags
    with st.expander("🔧 TCP Flag Counts"):
        col13, col14, col15 = st.columns(3)
        with col13:
            fin = st.number_input("FIN Flag Count", 0, 10, 0)
            rst = st.number_input("RST Flag Count", 0, 10, 0)
        with col14:
            syn = st.number_input("SYN Flag Count", 0, 10, 1)
            psh = st.number_input("PSH Flag Count", 0, 10, 0)
        with col15:
            ack = st.number_input("ACK Flag Count", 0, 10, 1)

    # Predict button
    submitted = st.form_submit_button("🚀 Predict Attack Type")

    if submitted:
        try:
            features = [
                dest_port, flow_duration, total_fwd, total_bwd,
                fwd_len_total, bwd_len_total, fwd_len_max, bwd_len_max,
                flow_bps, flow_pps, pkt_len_mean, pkt_len_std,
                fin, syn, rst, psh, ack
            ]

            input_array = np.array([features])
            prediction = model.predict(input_array)[0]
            proba = model.predict_proba(input_array)[0]
            label = attack_types[prediction]
            confidence = proba[prediction] * 100

            st.success(f"🧠 Prediction: **{label}**")
            st.info(f"Confidence: **{confidence:.2f}%**")

        except Exception as e:
            st.error(f"❌ Error: {e}")
