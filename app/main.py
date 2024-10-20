from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import APIKeyHeader
from .services import email_validator, rate_limiter
from .config import Config

app = FastAPI()

# API Key Security
API_KEY_NAME = "api_key"
api_key_header = APIKeyHeader(name=API_KEY_NAME)

async def get_api_key(api_key: str = Depends(api_key_header)):
    if not api_key:
        raise HTTPException(status_code=401, detail="API Key is missing")
    return api_key

# Dependency Injection for Rate Limiter
rate_limiter_instance = rate_limiter.SlidingWindowRateLimiter(rate_limit=100)

@app.get("/health")
async def health():
    """Returns the health status of the API."""
    return {"status": "ok"}

@app.post("/validate")
async def validate_email(email: str, api_key: str = Depends(get_api_key)):
    """Validates a single email address."""
    try:
        await rate_limiter_instance.acquire()
        validator = email_validator.EmailValidator(Config())
        result = await validator.validate_email_address(email)
        return result
    except Exception as e:
        return {"error": str(e)}

@app.post("/validate/bulk")
async def validate_emails(emails: list[str], api_key: str = Depends(get_api_key)):
    """Validates a list of email addresses."""
    if not emails:
        return {"error": "No emails provided"}
    try:
        await rate_limiter_instance.acquire()
        validator = email_validator.EmailValidator(Config())
        results = await validator.validate_emails(emails)
        return results
    except Exception as e:
        return {"error": str(e)}

