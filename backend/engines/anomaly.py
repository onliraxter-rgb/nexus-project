import pandas as pd
import numpy as np

def detect_anomalies(df: pd.DataFrame, config: dict):
    """
    Anomaly Root Cause Analysis Engine for NEXUS.
    Detects outliers, negative values, and suspicious frequency.
    """
    det_cols = config.get('detected_cols', {})
    rev_col = det_cols.get('revenue')
    user_col = det_cols.get('user_id')
    date_col = det_cols.get('date')

    anomalies = []

    # 1. Negative Values Check (Zero Tolerance)
    if rev_col in df.columns:
        neg_vals = df[df[rev_col] < 0]
        for _, row in neg_vals.iterrows():
            anomalies.append({
                "type": "NEGATIVE_REVENUE",
                "severity": "HIGH",
                "value": row[rev_col],
                "reason": "Revenue cannot be negative in a single transaction",
                "impact": abs(row[rev_col])
            })

    # 2. Z-Score Outlier Detection (Extreme Values)
    if rev_col in df.columns and len(df) > 10:
        mean = df[rev_col].mean()
        std = df[rev_col].std()
        if std > 0:
            df['z_score'] = (df[rev_col] - mean) / std
            outliers = df[df['z_score'].abs() > 3]
            for _, row in outliers.iterrows():
                anomalies.append({
                    "type": "STATISTICAL_OUTLIER",
                    "severity": "MEDIUM",
                    "value": row[rev_col],
                    "reason": f"Value is {round(row['z_score'], 1)} standard deviations from mean",
                    "impact": row[rev_col]
                })

    # 3. Frequency Anomaly (Bulk Orders by User)
    if user_col in df.columns and date_col in df.columns:
        df_sorted = df.sort_values(by=[user_col, date_col])
        df_sorted['time_diff'] = df_sorted.groupby(user_col)[date_col].diff().dt.total_seconds()
        suspicious_orders = df_sorted[df_sorted['time_diff'] < 10]  # Orders < 10s apart
        for _, row in suspicious_orders.iterrows():
            anomalies.append({
                "type": "SUSPICIOUS_FREQUENCY",
                "severity": "HIGH",
                "value": row[user_col],
                "reason": "Multiple orders placed by same user in under 10 seconds",
                "impact": 0
            })

    return {
        "anomalies": anomalies,
        "count": len(anomalies)
    }
