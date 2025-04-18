from fastapi import FastAPI, Request
import re
import dns.resolver

app = FastAPI()

# Blocked local parts (role-based emails)
blocked_prefixes = {"info", "admin", "support", "sales", "contact", "noreply", "no-reply", "help", "service", "billing"}

def is_valid_syntax(email):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email)

def is_blocked_email(email):
    local_part = email.split('@')[0].lower()
    return local_part in blocked_prefixes

def has_mx_record(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return len(mx_records) > 0
    except:
        return False

@app.post("/verify")
async def verify(request: Request):
    data = await request.json()
    email = data.get("email")
    if not email:
        return {"status": "error", "message": "No email provided"}

    if not is_valid_syntax(email):
        return {"email": email, "status": "invalid", "reason": "Bad Syntax"}

    if is_blocked_email(email):
        return {"email": email, "status": "invalid", "reason": "Role-based email not allowed"}

    domain = email.split('@')[1]
    if not has_mx_record(domain):
        return {"email": email, "status": "invalid", "reason": "No MX Record"}

    return {"email": email, "status": "valid"}
