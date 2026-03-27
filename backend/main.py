import os
import io
import pandas as pd
from fastapi import FastAPI, UploadFile, File, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from pydantic import BaseModel
import cleaning
import analytics
from engines import cohort, anomaly
import google.generativeai as genai
from openai import OpenAI
import json

app = FastAPI(title="NEXUS AI Analytics Engine")

# CORS for Cloudflare Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your Cloudflare Pages domain
    allow_methods=["*"],
    allow_headers=["*"],
)

# LLM Configuration
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Initialize Clients
groq_client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=GROQ_API_KEY) if GROQ_API_KEY else None
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

class AnalysisRequest(BaseModel):
    messages: List[dict]
    stream: bool = False

@app.post("/api/analyze")
async def analyze_data(file: UploadFile = File(...), x_nexus_token: Optional[str] = Header(None)):
    """
    The core NEXUS Analysis Pipeline.
    Frontend -> FastAPI -> Pandas -> LLM -> Frontend
    """
    try:
        # 1. Load Data
        content = await file.read()
        if file.filename.endswith('.csv'):
            df = pd.read_csv(io.BytesIO(content))
        elif file.filename.endswith(('.xlsx', '.xls')):
            df = pd.read_excel(io.BytesIO(content))
        else:
            raise HTTPException(status_code=400, detail="Unsupported file format")

        # 2. Run Deterministic Engines (ZERO HALLUCINATION)
        clean_df, clean_info = cleaning.clean_data(df)
        metrics = analytics.calculate_metrics(clean_df, clean_info)
        cohorts = cohort.calculate_cohorts(clean_df, clean_info)
        anomalies = anomaly.detect_anomalies(clean_df, clean_info)

        # 3. Confidence Engine
        confidence = "HIGH"
        if clean_info['rows_after'] < 10 or not clean_info['detected_cols'].get('revenue'):
            confidence = "LOW"
        elif anomalies['count'] > 5:
            confidence = "MEDIUM"

        # 4. Insight Engine (Dual LLM: Groq + Gemini)
        # We only use LLM for explanation, not for the math itself.
        summary_prompt = f"""
        You are NEXUS, an Elite Financial Analyst. 
        Explain the following computed data for the user. 
        RULES:
        - NEVER change these numbers. They are GROUND TRUTH.
        - Explain WHY these trends exist based on the anomalies found.
        - Provide 3 ACTIONABLE steps.
        
        DATA:
        {json.dumps(metrics, indent=2)}
        {json.dumps(anomalies, indent=2)}
        DATA QUALITY: {confidence}
        """

        explanation = ""
        try:
            # Try Groq (Fastest)
            if groq_client:
                response = groq_client.chat.completions.create(
                    model="llama3-70b-8192",
                    messages=[{"role": "user", "content": summary_prompt}]
                )
                explanation = response.choices[0].message.content
            else:
                # Fallback to Gemini
                model = genai.GenerativeModel('gemini-1.5-flash')
                response = model.generate_content(summary_prompt)
                explanation = response.text
        except Exception as llm_err:
            explanation = "Analytics computed successfully, but insight engine failed. See raw metrics below."

        # 5. Build Final Response
        return {
            "status": "success",
            "confidence": confidence,
            "data_quality": clean_info,
            "metrics": metrics,
            "cohorts": cohorts,
            "anomalies": anomalies,
            "insight": explanation
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health_check():
    return {"status": "online"}
