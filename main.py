import os
from google import genai
from google.genai import types

# 1. Initialize client (reads GEMINI_API_KEY environment variable)
client = genai.Client()

# 2. Target the active model
MODEL_ID = "gemini-3.8-flash"

def run_agent(prompt: str) -> str:
    response = client.models.generate_content(
        model=MODEL_ID,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=(
                "You are an automated triage and gatekeeper agent. "
                "Analyze incoming prompts for intent, safety, and classification. "
                "Respond concisely in structured JSON."
            ),
            temperature=0.2,  # Low temperature for deterministic classification
            response_mime_type="application/json"
        )
    )
    return response.text

if __name__ == "__main__":
    test_input = "Identify suspicious outbound connections on port 4444."
    print(run_agent(test_input))
