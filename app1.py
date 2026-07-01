# =====================================
# AI BASED FILE INTEGRITY MONITORING
# AND ANOMALY DETECTION SYSTEM
# =====================================

import streamlit as st
import pandas as pd
import numpy as np
import pickle
import os
import matplotlib.pyplot as plt
from io import BytesIO

# =====================================
# PAGE SETTINGS
# =====================================

st.set_page_config(
    page_title="Integrity Monitor",
    layout="centered"
)

# =====================================
# STYLE (Pleasant Dashboard Background)
# =====================================

st.markdown("""
<style>

.main-card {
    background: linear-gradient(
        135deg,
        #e3f2fd,
        #f1f8e9
    );
    padding: 18px;
    border-radius: 12px;
    box-shadow: 0 3px 8px rgba(0,0,0,0.1);
}

.title-style {
    text-align: center;
    font-size: 16px;
    font-weight: 600;
}

</style>
""", unsafe_allow_html=True)

st.markdown(
    """
    <div class="title-style">
    AI-Based File Integrity Monitoring & Anomaly Detection
    </div>
    """,
    unsafe_allow_html=True
)

# =====================================
# LOAD MODELS
# =====================================

rf_model_path = "model_rf.pkl"
if_model_path = "model_if.pkl"

if not os.path.exists(rf_model_path):
    st.error("Random Forest model missing")
    st.stop()

if not os.path.exists(if_model_path):
    st.error("Isolation Forest model missing")
    st.stop()

rf_model = pickle.load(open(rf_model_path, "rb"))
if_model = pickle.load(open(if_model_path, "rb"))

# =====================================
# FILE UPLOAD
# =====================================

uploaded_file = st.file_uploader(
    "Upload Log File",
    type="csv"
)

# =====================================
# EXCEL REPORT FUNCTION
# =====================================

def create_excel(summary_df):

    output = BytesIO()

    with pd.ExcelWriter(
        output,
        engine="openpyxl"
    ) as writer:

        summary_df.to_excel(
            writer,
            index=False,
            sheet_name="Security Report"
        )

    output.seek(0)

    return output

# =====================================
# MAIN PROCESS
# =====================================

if uploaded_file is not None:

    try:

        data = pd.read_csv(uploaded_file)

        X = data.drop(
            "is_malicious",
            axis=1,
            errors="ignore"
        )

        # Encode categorical data

        for column in X.columns:

            if X[column].dtype == "object":

                X[column] = (
                    X[column]
                    .astype("category")
                    .cat.codes
                )

        # =====================================
        # RUN SECURITY ANALYSIS
        # =====================================

        if st.button("Run Security Analysis"):

            # Random Forest

            rf_predictions = rf_model.predict(X)

            # Isolation Forest

            if_predictions = if_model.predict(X)

            if_predictions = np.where(
                if_predictions == -1,
                1,
                0
            )

            # Combined decision

            final_predictions = np.where(
                (rf_predictions == 1)
                | (if_predictions == 1),
                1,
                0
            )

            normal_count = int(
                np.sum(final_predictions == 0)
            )

            anomaly_count = int(
                np.sum(final_predictions == 1)
            )

            total_records = len(
                final_predictions
            )

            risk_score = (
                anomaly_count
                / total_records
            ) * 100

            # =====================================
            # RISK LEVEL
            # =====================================

            if risk_score <= 20:

                risk_level = "Low"
                alert_message = "System operating normally"

            elif risk_score <= 50:

                risk_level = "Medium"
                alert_message = "Monitoring recommended"

            else:

                risk_level = "High"
                alert_message = "Potential threat detected"

            # =====================================
            # DEPARTMENT IDENTIFICATION
            # =====================================

            if (
                "employee_department"
                in data.columns
                and anomaly_count > 0
            ):

                malicious_departments = (
                    data.loc[
                        final_predictions == 1,
                        "employee_department"
                    ]
                    .value_counts()
                )

                top_department = (
                    malicious_departments.idxmax()
                )

            else:

                top_department = "N/A"

            # =====================================
            # DASHBOARD PANEL
            # =====================================

            st.markdown(
                '<div class="main-card">',
                unsafe_allow_html=True
            )

            # =====================================
            # METRIC ROW
            # =====================================

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Total Records",
                total_records
            )

            col2.metric(
                "Normal Users",
                normal_count
            )

            col3.metric(
                "Malicious Users",
                anomaly_count
            )

            st.write("")

            # =====================================
            # STATUS INDICATOR
            # =====================================

            if risk_level == "Low":

                st.success(
                    "System Status: Secure"
                )

            elif risk_level == "Medium":

                st.warning(
                    "System Status: Monitoring Required"
                )

            else:

                st.error(
                    "System Status: Threat Detected"
                )

            st.write(
                "Risk Score:",
                round(risk_score, 2),
                "%"
            )

            st.write(
                "Department with Malicious Access:",
                top_department
            )

            # =====================================
            # DONUT CHART
            # =====================================

            labels = [
                "Normal",
                "Anomaly"
            ]

            values = [
                normal_count,
                anomaly_count
            ]

            colors = [
                "#4CAF50",
                "#F44336"
            ]

            fig, ax = plt.subplots(
                figsize=(2.6, 2.6)
            )

            ax.pie(
                values,
                labels=labels,
                colors=colors,
                autopct="%1.1f%%",
                startangle=90,
                textprops={
                    "fontsize": 6,
                    "weight": "bold"
                }
            )

            centre_circle = plt.Circle(
                (0, 0),
                0.72,
                fc="white"
            )

            fig.gca().add_artist(
                centre_circle
            )

            ax.axis("equal")

            st.pyplot(fig)

            st.markdown(
                '</div>',
                unsafe_allow_html=True
            )

            # =====================================
            # SUMMARY REPORT
            # =====================================

            summary_df = pd.DataFrame({

                "Total Records":
                [total_records],

                "Normal Users":
                [normal_count],

                "Malicious Users":
                [anomaly_count],

                "Department with Malicious Access":
                [top_department],

                "Risk Score (%)":
                [round(risk_score, 2)],

                "Risk Level":
                [risk_level],

                "Alert":
                [alert_message]

            })

            excel_file = create_excel(
                summary_df
            )

            st.download_button(

                label="Download Security Report",

                data=excel_file,

                file_name="Security_Report.xlsx",

                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

            )

    except Exception as e:

        st.error("Processing error")
        st.write(e)