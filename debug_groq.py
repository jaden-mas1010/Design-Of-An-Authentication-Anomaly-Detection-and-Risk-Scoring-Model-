import os
import httpx

api_key = os.environ.get("GROQ_API_KEY")
print(f"Key present: {bool(api_key)}")
print(f"Key starts with: {api_key[:10] if api_key else 'N/A'}...")

try:
    response = httpx.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "model": "openai/gpt-oss-20b",
            "messages": [{"role": "user", "content": "Say hello in one sentence."}],
            "max_tokens": 400,
        },
        timeout=10.0,
    )
    print(f"Status code: {response.status_code}")
    print(f"Response body: {response.text}")
except Exception as e:
    print(f"Exception type: {type(e).__name__}")
    print(f"Exception message: {e}")
