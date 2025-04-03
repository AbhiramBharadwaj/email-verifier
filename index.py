from fastapi import FastAPI
from pydantic import BaseModel, EmailStr
import dns.resolver
import re

app = FastAPI()

class EmailRequest(BaseModel):
    email: EmailStr

# List of blocked prefixes (role-based accounts)
blocked_prefixes = {
    "info", "support", "admin", "sales", "contact", "noreply",
    "no-reply", "help", "service", "billing", "office", "hr"
}

# Sample disposable domains (expand this list for production)
disposable_domains = {
    "tempmail.com", "10minutemail.com", "mailinator.com", "guerrillamail.com"
}

def is_blocked_prefix(local_part: str) -> bool:
    # Exact match
    if local_part.lower() in blocked_prefixes:
        return True
    # Partial match like info123, support_team etc.
    for prefix in blocked_prefixes:
        if local_part.lower().startswith(prefix):
            return True
    return False

def is_disposable_domain(domain: str) -> bool:
    return domain.lower() in disposable_domains

def has_mx_record(domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5.0)
        return len(answers) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers):
        return False

@app.post("/verify")
async def verify_email(req: EmailRequest):
    email = req.email
    local_part, domain = email.split('@', 1)

    # Block role-based emails
    if is_blocked_prefix(local_part):
        return {"email": email, "status": "invalid", "reason": "Role-based email not allowed"}

    # Block disposable domains
    if is_disposable_domain(domain):
        return {"email": email, "status": "invalid", "reason": "Disposable email domain"}

    # Check MX Records
    if not has_mx_record(domain):
        return {"email": email, "status": "invalid", "reason": "No MX Record"}

    return {"email": email, "status": "valid"}

