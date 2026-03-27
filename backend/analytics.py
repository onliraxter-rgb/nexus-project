import pandas as pd
import numpy as np

def calculate_metrics(df: pd.DataFrame, config: dict):
    """
    Deterministic KPI engine for NEXUS.
    No math in LLM - all math done here via pandas.
    """
    metrics = {
        "revenue": 0,
        "orders": 0,
        "aov": 0,
        "unique_users": 0,
        "avg_daily_revenue": 0,
        "growth": 0,
        "revenue_trend": []
    }
    
    det_cols = config.get('detected_cols', {})
    rev_col = det_cols.get('revenue')
    date_col = det_cols.get('date')
    user_col = det_cols.get('user_id')

    # 1. Revenue & Orders
    if rev_col in df.columns:
        metrics['revenue'] = round(df[rev_col].sum(), 2)
        metrics['orders'] = len(df)
        metrics['aov'] = round(metrics['revenue'] / metrics['orders'] if metrics['orders'] > 0 else 0, 2)
    else:
        metrics['revenue'] = None
        metrics['orders'] = None
        metrics['aov'] = "Not enough data"

    # 2. Unique Users
    if user_col in df.columns:
        metrics['unique_users'] = df[user_col].nunique()
    else:
        metrics['unique_users'] = "Not enough data"

    # 3. Time-Series Trends (Daily Revenue)
    if rev_col in df.columns and date_col in df.columns:
        df[date_col] = pd.to_datetime(df[date_col])
        daily_rev = df.groupby(df[date_col].dt.date)[rev_col].sum().reset_index()
        daily_rev.columns = ['name', 'val']
        daily_rev['name'] = daily_rev['name'].apply(lambda x: x.strftime('%Y-%m-%d'))
        metrics['revenue_trend'] = daily_rev.to_dict('records')
        
        # Simple Growth (Last 7 days vs Previous 7 days)
        if len(daily_rev) >= 14:
            curr_week = daily_rev['val'].iloc[-7:].sum()
            prev_week = daily_rev['val'].iloc[-14:-7].sum()
            metrics['growth'] = round(((curr_week - prev_week) / prev_week * 100), 1) if prev_week > 0 else 0

    return metrics
