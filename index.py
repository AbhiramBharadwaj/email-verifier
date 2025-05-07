from fastapi import FastAPI, Request
import re
import dns.resolver
import aiosmtplib
import asyncio

app = FastAPI()

blocked_prefixes = {
    "info", "admin", "support", "sales", "contact", "noreply", "no-reply",
    "help", "service", "billing", "webmaster", "security", "marketing",
    "abuse", "postmaster", "hostmaster", "root", "system", "mail", "mailer"
}

def is_valid_syntax(email: str) -> bool:
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

async def smtp_verify_email(email: str) -> str:
    domain = email.split('@')[1]
    try:
        # Fetch MX records for the domain
        mx_records = await asyncio.to_thread(dns.resolver.resolve, domain, 'MX')
        mx_server = str(mx_records[0].exchange).rstrip('.')
        print(f"[✅ SMTP CHECK] Using MX Server: {mx_server}")

        # Try only one SMTP port (25) with a short timeout
        smtp_client = aiosmtplib.SMTP(hostname=mx_server, port=25, timeout=3)
        await smtp_client.connect()
        await smtp_client.ehlo()

        response_rcpt = await smtp_client.mail("")
        response_rcpt = await smtp_client.rcpt(email)
        await smtp_client.quit()

        if response_rcpt[0] == 250:
            return "valid"
        else:
            return "unverified"

    except (aiosmtplib.SMTPException, Exception):
        return "unverified"

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

    smtp_status = await smtp_verify_email(email)
    if smtp_status == "valid":
        return {"email": email, "status": "valid"}
    else:
        return {"email": email, "status": "unverified", "reason": "SMTP verification failed"}
