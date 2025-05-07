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

        # Try multiple SMTP ports (25, 587, 465)
        ports = [25, 587, 465]
        for port in ports:
            try:
                print(f"[🔍 TRYING SMTP] {mx_server}:{port}")
                smtp_client = aiosmtplib.SMTP(hostname=mx_server, port=port, timeout=5)
                await smtp_client.connect()
                await smtp_client.ehlo()

                response_rcpt = await smtp_client.mail("")
                response_rcpt = await smtp_client.rcpt(email)
                await smtp_client.quit()

                if response_rcpt[0] == 250:
                    return "valid"
            except aiosmtplib.SMTPException as e:
                print(f"[❌ SMTP ERROR on {port}] {e}")
                continue  # Try the next port

        return "unverified"  # Unable to verify, but not necessarily invalid

    except dns.resolver.NoAnswer:
        print("[❌ SMTP CHECK] No MX records found for the domain.")
        return "invalid"
    except dns.resolver.NXDOMAIN:
        print("[❌ SMTP CHECK] Domain does not exist.")
        return "invalid"
    except Exception as e:
        print(f"[❌ UNKNOWN ERROR] {e}")
        return "unverified"  # Unable to verify

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
    elif smtp_status == "unverified":
        return {"email": email, "status": "unverified", "reason": "SMTP verification failed or blocked"}
    else:
        return {"email": email, "status": "invalid", "reason": "SMTP verification failed"}
