from fastapi import FastAPI, Request
import re
import dns.resolver
import asyncio

app = FastAPI()

# Expanded list of blocked role-based emails
blocked_prefixes = {
    "info", "admin", "support", "sales", "contact", "noreply", "no-reply",
    "help", "service", "billing", "webmaster", "security", "marketing",
    "abuse", "postmaster", "hostmaster", "root", "system", "mail", "mailer"
}

# More accurate regex for email syntax validation
def is_valid_syntax(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

def is_blocked_email(email: str) -> bool:
    local_part = email.split('@')[0].lower()
    return local_part in blocked_prefixes

async def has_mx_record(domain: str) -> bool:
    try:
        # Use async DNS lookup for faster response
        mx_records = await asyncio.to_thread(dns.resolver.resolve, domain, 'MX')
        return len(mx_records) > 0
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.Timeout:
        return False
    except Exception:
        return False

@app.post("/verify")
async def verify(request: Request):
    data = await request.json()
    email = data.get("email")
    if not email:
        return {"status": "error", "message": "No email provided"}

    # Step 1: Syntax Validation
    if not is_valid_syntax(email):
        return {"email": email, "status": "invalid", "reason": "Bad Syntax"}

    # Step 2: Blocked Role-Based Email Check
    if is_blocked_email(email):
        return {"email": email, "status": "invalid", "reason": "Role-based email not allowed"}

    # Step 3: MX Record Validation (Async)
    domain = email.split('@')[1]
    if not await has_mx_record(domain):
        return {"email": email, "status": "invalid", "reason": "No MX Record"}

    # If all checks pass
    return {"email": email, "status": "valid"}
