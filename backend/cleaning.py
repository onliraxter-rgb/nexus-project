import pandas as pd
import numpy as np
import re
from datetime import datetime

def clean_data(df: pd.DataFrame):
    """
    Advanced cleaning suite for NEXUS.
    Returns cleaned DF and diagnostic info.
    """
    issues = []
    rows_before = len(df)
    
    # 1. Remove complete duplicates
    df = df.drop_duplicates()
    if len(df) < rows_before:
        issues.append(f"Removed {rows_before - len(df)} duplicate rows")

    # 2. Column Auto-Detection & Mapping
    mapping = {
        'revenue': ['amount', 'final_amount', 'price', 'sale_price', 'revenue', 'sales', 'total_amount', 'grand_total'],
        'date': ['date', 'timestamp', 'created_at', 'order_date', 'transaction_date', 'signup_date'],
        'user_id': ['user_id', 'customer_id', 'cust_id', 'client_id', 'email', 'uid'],
        'category': ['category', 'type', 'group', 'department']
    }
    
    detected_cols = {}
    for standard_name, aliases in mapping.items():
        for col in df.columns:
            if col.lower().strip() in aliases or any(alias in col.lower() for alias in aliases):
                detected_cols[standard_name] = col
                break

    # 3. Safe Numeric Conversion for Revenue
    if 'revenue' in detected_cols:
        rev_col = detected_cols['revenue']
        df[rev_col] = df[rev_col].apply(lambda x: re.sub(r'[^\d.]', '', str(x)) if pd.notnull(x) else x)
        df[rev_col] = pd.to_numeric(df[rev_col], errors='coerce')
        nan_count = df[rev_col].isna().sum()
        if nan_count > 0:
            issues.append(f"Dropped {nan_count} rows with invalid revenue values")
            df = df.dropna(subset=[rev_col])

    # 4. Date Normalization
    if 'date' in detected_cols:
        date_col = detected_cols['date']
        df[date_col] = pd.to_datetime(df[date_col], errors='coerce')
        nan_dates = df[date_col].isna().sum()
        if nan_dates > 0:
            issues.append(f"Dropped {nan_dates} rows with invalid date formats")
            df = df.dropna(subset=[date_col])

    # 5. Outlier Detection (Percentile-based)
    if 'revenue' in detected_cols:
        rev_col = detected_cols['revenue']
        upper_limit = df[rev_col].quantile(0.99)
        outliers = df[df[rev_col] > upper_limit]
        if not outliers.empty:
            issues.append(f"Flagged {len(outliers)} rows as extreme outliers (>99th percentile)")
            # We keep them but flag them for the Anomaly Engine later

    return df, {
        "rows_before": rows_before,
        "rows_after": len(df),
        "issues": issues,
        "detected_cols": detected_cols
    }
