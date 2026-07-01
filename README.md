# RiskLens

A Python-based interactive dashboard for detecting anomalous user activity 
and scoring security risk from system logs.

## Overview

Large organizations generate high volumes of system activity logs, making it 
difficult to manually catch suspicious behavior — unauthorized access, 
abnormal file activity, or insider misuse of resources. RiskLens uses two 
machine learning models to flag anomalous records and convert the results 
into a simple risk score, so a system administrator can quickly judge how 
serious a situation is and what to do next.

## How it works

1. Upload a CSV log file containing user activity records (department, 
   file-transfer behavior, login patterns, etc.).
2. Two machine learning models — one supervised, one unsupervised — 
   independently classify each record as normal or suspicious.
3. Their outputs are combined: a record is flagged as an anomaly if either 
   model considers it suspicious.
4. The dashboard displays:
   - Total records, normal count, anomaly count
   - A risk score (percentage of records flagged as anomalous)
   - A risk level — Low / Medium / High
   - The department with the most flagged activity, if available
5. Results can be exported as a downloadable Excel report.

## Tech stack

Python, with a web-based dashboard interface and standard data science 
libraries (Pandas, NumPy, Scikit-learn, Matplotlib).

## Notes

- Pre-trained model files are not included in this repo — the app expects 
  `model_rf.pkl` and `model_if.pkl` to be present locally to run.
- This is a demonstration/portfolio project exploring anomaly detection and 
  risk-scoring techniques — not a production-ready monitoring tool.

## Future improvements

- Real-time log ingestion
- More advanced ensemble ML approaches
- Automated alerting on high-risk thresholds
- Support for larger-scale log processing
