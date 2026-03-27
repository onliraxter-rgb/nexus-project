import pandas as pd
import numpy as np

def calculate_cohorts(df: pd.DataFrame, config: dict):
    """
    Cohort Analysis Engine for NEXUS.
    Calculates retention matrix based on first purchase.
    """
    det_cols = config.get('detected_cols', {})
    user_id = det_cols.get('user_id')
    date_col = det_cols.get('date')

    if not user_id or not date_col or user_id not in df.columns or date_col not in df.columns:
        return {"retention_matrix": None, "message": "Not enough data for cohorts"}

    # 1. Create Cohort Groups
    df['order_month'] = df[date_col].dt.to_period('M')
    df['cohort_month'] = df.groupby(user_id)[date_col].transform('min').dt.to_period('M')

    # 2. Assign Cohort Periods
    def get_period(record):
        return (record['order_month'] - record['cohort_month']).n

    df['cohort_index'] = df.apply(get_period, axis=1)

    # 3. Create Retention Matrix
    cohort_data = df.groupby(['cohort_month', 'cohort_index'])[user_id].nunique().reset_index()
    matrix = cohort_data.pivot(index='cohort_month', columns='cohort_index', values=user_id)
    
    # 4. Convert to Percentage
    cohort_size = matrix.iloc[:, 0]
    retention = matrix.divide(cohort_size, axis=0).round(3) * 100
    
    # Clean up for JSON
    retention.index = retention.index.astype(str)
    return {
        "retention_matrix": retention.fillna(0).to_dict('index'),
        "cohort_sizes": cohort_size.to_dict()
    }
