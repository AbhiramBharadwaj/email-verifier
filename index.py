from fastapi import FastAPI, Request
import re
import dns.resolver
import aiosmtplib

app = FastAPI()

# Enhanced blocked local parts (role-based emails)
blocked_prefixes = {
    "info", "admin", "support", "sales", "contact", "noreply", "no-reply",
    "help", "service", "billing", "webmaster", "security", "marketing",
    "abuse", "postmaster", "hostmaster", "root", "system", "mail", "mailer"
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
        mx_records = dns.resolver.resolve(domain, 'MX')
        return len(mx_records) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return False

async def smtp_verify_email(email: str) -> bool:
    domain = email.split('@')[1]

    try:
        # Fetch MX records for the domain
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_server = str(mx_records[0].exchange).rstrip('.')
        print(f"[✅ SMTP CHECK] Using MX Server : {mx_server}")

        # Connect to the MX server using SMTP
        smtp_client = aiosmtplib.SMTP(hostname=mx_server, port=25, timeout=10)
        await smtp_client.connect()
        await smtp_client.ehlo()

        # SMTP VRFY (Verify) and RCPT TO (Recipient) commands
        response_vrfy = await smtp_client.vrfy(email)
        print(f"[🔍 VRFY Response]: {response_vrfy}")

        # If VRFY is not supported, use RCPT TO
        response_rcpt = await smtp_client.mail("")
        response_rcpt = await smtp_client.rcpt(email)
        print(f"[🔍 RCPT Response]: {response_rcpt}")

        await smtp_client.quit()

        # If the server accepts the email, it is valid
        if response_rcpt[0] == 250:
            return True
        else:
            print(f"[❌ SMTP CHECK] Email not accepted: {response_rcpt}")
            return False

    except dns.resolver.NoAnswer:
        print("[❌ SMTP CHECK] No MX records found for the domain.")
        return False
    except dns.resolver.NXDOMAIN:
        print("[❌ SMTP CHECK] Domain does not exist.")
        return False
    except aiosmtplib.SMTPException as e:
        print(f"[❌ SMTP ERROR] {e}")
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

    # Step 1: Syntax Validation
    if not is_valid_syntax(email):
        return {"email": email, "status": "invalid", "reason": "Bad Syntax"}

    # Step 2: Blocked Role-Based Email Check
    if is_blocked_email(email):
        return {"email": email, "status": "invalid", "reason": "Role-based email not allowed"}

    # Step 3: MX Record Validation
    domain = email.split('@')[1]
    if not await has_mx_record(domain):
        return {"email": email, "status": "invalid", "reason": "No MX Record"}

    # Step 4: Advanced SMTP Verification
    is_smtp_valid = await smtp_verify_email(email)
    if not is_smtp_valid:
        return {"email": email, "status": "invalid", "reason": "SMTP verification failed"}

    # If all checks pass
    return {"email": email, "status": "valid"}
