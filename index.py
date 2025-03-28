from fastapi import FastAPI, Request
import re
import dns.resolver

app = FastAPI()

def is_valid_syntax(email):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email)

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

    domain = email.split('@')[1]
    if not has_mx_record(domain):
        return {"email": email, "status": "invalid", "reason": "No MX Record"}

    return {"email": email, "status": "valid"}
