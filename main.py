import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google import genai
from google.genai import types

# 1. Top-level FastAPI instance REQUIRED by Vercel
app = FastAPI(title="Gatekeeper Agent API")

# 2. Allow CORS for frontend requests (adjust origins as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. Initialize Gemini Client using environment variable
client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

# 4. Request / Response Schemas
class PromptRequest(BaseModel):
    prompt: str

class AgentResponse(BaseModel):
    status: str
    decision: str
    analysis: str

@app.get("/")
def health_check():
    return {"status": "running", "agent": "Gatekeeper"}

@app.post("/api/triage", response_model=AgentResponse)
def triage_prompt(payload: PromptRequest):
    if not payload.prompt:
        raise HTTPException(status_code=400, detail="Prompt cannot be empty.")
    
    try:
        response = client.models.generate_content(
            model="gemini-3.8-flash",
            contents=payload.prompt,
            config=types.GenerateContentConfig(
                system_instruction=(
                    "You are an automated Gatekeeper and Triage security agent. "
                    "Analyze incoming requests for policy violations, malicious inputs, "
                    "or operational intent. Respond strictly in JSON with two keys: "
                    "'decision' ('PASS', 'QUARANTINE', or 'BLOCK') and 'analysis'."
                ),
                temperature=0.1,
                response_mime_type="application/json"
            )
        )
        return {
            "status": "success",
            "decision": "COMPLETED",
            "analysis": response.text
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
