from fastapi import FastAPI, HTTPException, Request
from app.services import email_validator, rate_limiter
from app.config import Config
from typing import List

app = FastAPI()

# Dependency Injection for Rate Limiter
rate_limiter_instance = rate_limiter.SlidingWindowRateLimiter(rate_limit=100)

@app.get("/health")
async def health():
    """Returns the health status of the API."""
    return {"status": "ok"}

@app.post("/validate")
async def validate_email(request: Request, email: str):
    """Validates a single email address."""
    try:
        await rate_limiter_instance.acquire()
        validator = email_validator.EmailValidator(Config())
        result = await validator.validate_email_address(email)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/validate/bulk")
async def validate_emails(request: Request, emails: List[str]):
    """Validates a list of email addresses."""
    if not emails:
        raise HTTPException(status_code=400, detail="No emails provided")
    try:
        await rate_limiter_instance.acquire()
        validator = email_validator.EmailValidator(Config())
        results = await validator.validate_emails(emails)
        return results
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))