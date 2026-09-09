import json
import logging
import google.generativeai as genai
from config import Config

logger = logging.getLogger(__name__)

# Configure Gemini
genai.configure(api_key=Config.GEMINI_API_KEY)
model = genai.GenerativeModel("gemini-1.5-pro")

SYSTEM_PROMPT = """
You are a senior SOC analyst with 20 years of experience. Analyze the provided security log.
Return ONLY valid JSON. Do not include any markdown formatting, explanations, or extra text.

The JSON must have these exact keys:
- "suspicious": boolean (true if malicious, false if benign)
- "confidence": integer (0 to 100, where 100 is certain)
- "explanation": string (concise threat description, max 2 sentences)
- "mitre_ids": list of strings (e.g., ["T1078", "T1059"])
- "response": string (specific containment, eradication, and recovery steps)

Log data:
{log_json}
"""

def analyze_log(log_entry: dict) -> dict:
    """Send the structured log to Gemini and parse the JSON response."""
    try:
        prompt = SYSTEM_PROMPT.format(log_json=json.dumps(log_entry, indent=2))
        response = model.generate_content(prompt)

        # Extract JSON from potential markdown wrappers
        raw_text = response.text.strip()
        if raw_text.startswith("```json"):
            raw_text = raw_text[7:]
        if raw_text.startswith("```"):
            raw_text = raw_text[3:]
        if raw_text.endswith("```"):
            raw_text = raw_text[:-3]
        raw_text = raw_text.strip()

        result = json.loads(raw_text)

        # Ensure all required keys exist
        defaults = {
            "suspicious": False,
            "confidence": 0,
            "explanation": "No explanation provided.",
            "mitre_ids": [],
            "response": "Investigate manually using standard procedures."
        }
        for key, default in defaults.items():
            if key not in result:
                result[key] = default

        return result

    except json.JSONDecodeError as e:
        logger.error(f"Gemini returned invalid JSON: {e}\nResponse: {raw_text}")
        return {
            "suspicious": False,
            "confidence": 0,
            "explanation": f"Failed to parse AI response: {str(e)}",
            "mitre_ids": [],
            "response": "Manual investigation required."
        }
    except Exception as e:
        logger.error(f"Gemini API error: {e}")
        return {
            "suspicious": False,
            "confidence": 0,
            "explanation": f"AI service unavailable: {str(e)}",
            "mitre_ids": [],
            "response": "Fallback to manual SOC playbooks."
        }
