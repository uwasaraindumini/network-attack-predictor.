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

# Function to safely convert input to float or int
def to_number(value, field_name, number_type=float):
    if value.strip() == "":
        raise ValueError(f"{field_name} is required.")
    try:
        return number_type(value)
    except ValueError:
        raise ValueError(f"{field_name} must be a valid number.")

with st.form("attack_form"):
    # First row
    col1, col2, col3 = st.columns(3)
    with col1:
        dest_port = st.text_input("Destination Port", placeholder="e.g., 80")
    with col2:
        flow_duration = st.text_input("Flow Duration (μs)", placeholder="e.g., 123456")
    with col3:
        total_fwd = st.text_input("Total Forward Packets", placeholder="e.g., 300")

    # Second row
    col4, col5, col6 = st.columns(3)
    with col4:
        total_bwd = st.text_input("Total Backward Packets", placeholder="e.g., 250")
    with col5:
        fwd_len_total = st.text_input("Total Length of Forward Packets", placeholder="e.g., 80000")
    with col6:
        bwd_len_total = st.text_input("Total Length of Backward Packets", placeholder="e.g., 60000")

    # Third row
    col7, col8, col9 = st.columns(3)
    with col7:
        fwd_len_max = st.text_input("Forward Packet Len Max", placeholder="e.g., 1500")
    with col8:
        bwd_len_max = st.text_input("Backward Packet Len Max", placeholder="e.g., 1400")
    with col9:
        flow_bps = st.text_input("Flow Bytes/sec", placeholder="e.g., 1000000")

    # Fourth row
    col10, col11, col12 = st.columns(3)
    with col10:
        flow_pps = st.text_input("Flow Packets/sec", placeholder="e.g., 1000")
    with col11:
        pkt_len_mean = st.text_input("Packet Len Mean", placeholder="e.g., 500")
    with col12:
        pkt_len_std = st.text_input("Packet Len Std", placeholder="e.g., 100")

    # Fifth row: Flags
    with st.expander("🔧 TCP Flag Counts"):
        col13, col14, col15 = st.columns(3)
        with col13:
            fin = st.text_input("FIN Flag Count", placeholder="e.g., 0")
            rst = st.text_input("RST Flag Count", placeholder="e.g., 0")
        with col14:
            syn = st.text_input("SYN Flag Count", placeholder="e.g., 1")
            psh = st.text_input("PSH Flag Count", placeholder="e.g., 0")
        with col15:
            ack = st.text_input("ACK Flag Count", placeholder="e.g., 1")

    # Submit button
    submitted = st.form_submit_button("🚀 Predict Attack Type")

    if submitted:
        try:
            # Convert all values
            features = [
                to_number(dest_port, "Destination Port", int),
                to_number(flow_duration, "Flow Duration", int),
                to_number(total_fwd, "Total Forward Packets", int),
                to_number(total_bwd, "Total Backward Packets", int),
                to_number(fwd_len_total, "Total Length of Forward Packets"),
                to_number(bwd_len_total, "Total Length of Backward Packets"),
                to_number(fwd_len_max, "Forward Packet Len Max"),
                to_number(bwd_len_max, "Backward Packet Len Max"),
                to_number(flow_bps, "Flow Bytes/sec"),
                to_number(flow_pps, "Flow Packets/sec"),
                to_number(pkt_len_mean, "Packet Len Mean"),
                to_number(pkt_len_std, "Packet Len Std"),
                to_number(fin, "FIN Flag Count", int),
                to_number(syn, "SYN Flag Count", int),
                to_number(rst, "RST Flag Count", int),
                to_number(psh, "PSH Flag Count", int),
                to_number(ack, "ACK Flag Count", int),
            ]

            # Make prediction
            input_array = np.array([features])
            prediction = model.predict(input_array)[0]
            proba = model.predict_proba(input_array)[0]
            label = attack_types[prediction]
            confidence = proba[prediction] * 100

            st.success(f"🧠 Prediction: **{label}**")
            st.info(f"Confidence: **{confidence:.2f}%**")

        except ValueError as ve:
            st.error(f"🚫 Input Error: {ve}")
        except Exception as e:
            st.error(f"❌ Unexpected Error: {e}")
