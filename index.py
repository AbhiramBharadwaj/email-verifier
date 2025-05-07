from fastapi import FastAPI, Request
import re
import dns.resolver
import asyncio
import aiosmtplib

app = FastAPI()

# Enhanced blocked local parts (role-based emails)
blocked_prefixes = {
    "info", "admin", "support", "sales", "contact", "noreply", "no-reply",
    "help", "service", "billing", "webmaster", "security", "marketing", "abuse"
}

def is_valid_syntax(email: str) -> bool:
    # Enhanced regex for email validation
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

def is_blocked_email(email: str) -> bool:
    local_part = email.split('@')[0].lower()
    return local_part in blocked_prefixes

async def has_mx_record(domain: str) -> bool:
    try:
        mx_records = await asyncio.to_thread(dns.resolver.resolve, domain, 'MX')
        return len(mx_records) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return False

async def smtp_check(email: str) -> bool:
    domain = email.split('@')[1]
    
    try:
        # Fetch MX records of the domain
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_server = str(mx_records[0].exchange).rstrip('.')
        print(f"[SMTP CHECK] Using MX Server: {mx_server}")

        # Try connecting to the MX server (port 25 for standard SMTP)
        smtp_client = aiosmtplib.SMTP(hostname=mx_server, port=25, timeout=5)
        await smtp_client.connect()
        await smtp_client.quit()
        return True

    except dns.resolver.NoAnswer:
        print("[❌ SMTP CHECK] No MX records found for the domain.")
        return False
    except dns.resolver.NXDOMAIN:
        print("[❌ SMTP CHECK] Domain does not exist.")
        return False
    except aiosmtplib.SMTPException as e:
        print(f"[❌ SMTP CHECK ERROR] SMTP connection failed: {e}")
        return False
    except Exception as e:
        print(f"[❌ UNKNOWN ERROR] {e}")
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
    if not await has_mx_record(domain):
        return {"email": email, "status": "invalid", "reason": "No MX Record"}

    # Optional: Uncomment to enable SMTP check (can be slow)
    if not await smtp_check(email):
        return {"email": email, "status": "invalid", "reason": "SMTP verification failed"}

    return {"email": email, "status": "valid"}
