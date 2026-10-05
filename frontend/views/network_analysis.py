import streamlit as st

from frontend.components.error_state import render_error
from frontend.components.loading import analysis_spinner
from frontend.components.result_card import render_result
from frontend.services.api_client import APIError, analyze_network
from ml.common.preprocessing import NETWORK_FEATURES

LABELS = {
    "duration": ("Durée du flux (secondes)", 0.0),
    "src_bytes": ("Octets envoyés", 0.0),
    "dst_bytes": ("Octets reçus", 0.0),
    "src_packets": ("Paquets envoyés", 0.0),
    "dst_packets": ("Paquets reçus", 0.0),
    "src_port": ("Port source", 0.0),
    "dst_port": ("Port destination", 0.0),
    "protocol_number": ("Protocole (TCP 6, UDP 17, ICMP 1)", 0.0),
    "flow_rate": ("Débit de paquets (paquets/seconde)", 0.0),
}
INTEGER_FEATURES = {
    "src_bytes", "dst_bytes", "src_packets", "dst_packets",
    "src_port", "dst_port", "protocol_number",
}


def render() -> None:
    st.subheader("Analyse d’un flux réseau")
    st.caption("Saisissez les caractéristiques d’un flux obtenu avec autorisation. Aucun balayage réseau n’est effectué.")
    with st.form("network_form"):
        fields = {
            feature: st.number_input(
                label=LABELS[feature][0],
                min_value=0.0,
                max_value=65535.0 if feature in {"src_port", "dst_port"} else 255.0 if feature == "protocol_number" else None,
                step=1.0 if feature in INTEGER_FEATURES else 0.1,
                value=LABELS[feature][1],
                key=f"network_{feature}",
            )
            for feature in NETWORK_FEATURES
        }
        submitted = st.form_submit_button("Analyser le flux", type="primary")
    if submitted:
        try:
            with analysis_spinner():
                result = analyze_network(fields)
            render_result(result, "Flux potentiellement malveillant", "Aucun signal malveillant détecté")
        except APIError as exc:
            render_error(str(exc))