# admin_auth.py  (Streamlit Cloud safe)
import streamlit as st
import os
import json
import random
import smtplib
from email.message import EmailMessage
from pathlib import Path

# Config - change these to your sender/master emails in env or keep as-is for testing
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS", "mpmc.projectpi@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "your_smtp_app_password")
MASTER_EMAIL = os.getenv("MASTER_EMAIL", "vartamame69@gmail.com")

ADMIN_DATA_DIR = Path("admin_data")
ADMIN_DATA_DIR.mkdir(exist_ok=True)
ADMIN_FILE = ADMIN_DATA_DIR / "admins.json"

def _load_admins():
    if not ADMIN_FILE.exists():
        return []
    try:
        with open(ADMIN_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def _save_admins(admins):
    with open(ADMIN_FILE, "w") as f:
        json.dump(admins, f, indent=2)

# ---------------- OTP Helpers ----------------
def send_email(to_email: str, subject: str, body: str):
    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

def send_master_otp():
    otp = str(random.randint(100000, 999999))
    send_email(MASTER_EMAIL, "Master OTP for admin registration", f"Your OTP: {otp}")
    return otp

def send_otp_to(email: str):
    otp = str(random.randint(100000, 999999))
    send_email(email, "Your Admin OTP", f"Your OTP for admin actions is: {otp}")
    return otp

# ---------------- Register Admin (master OTP -> add admin) ----------------
def register_new_admin():
    st.subheader("🛡️ Register Admin (OTP-based, no webcam)")

    # Step 0: verify master OTP first
    if "master_otp_sent" not in st.session_state:
        if st.button("Send Master OTP to Master Email"):
            st.session_state._master_otp = send_master_otp()
            st.session_state.master_otp_sent = True
            st.info(f"Master OTP sent to {MASTER_EMAIL}")
        return

    if "master_otp_verified" not in st.session_state:
        otp_input = st.text_input("Enter Master OTP (sent to master email)", type="password")
        if st.button("Verify Master OTP"):
            if otp_input == st.session_state.get("_master_otp"):
                st.success("Master OTP verified — you may register a new admin.")
                st.session_state.master_otp_verified = True
            else:
                st.error("Invalid master OTP.")
        return

    # Step 1: collect admin details and register
    name = st.text_input("Admin name")
    email = st.text_input("Admin email")

    if st.button("Register Admin"):
        if not name or not email:
            st.error("Enter both name and email.")
            return

        admins = _load_admins()
        # prevent duplicate emails
        if any(a["email"].lower() == email.lower() for a in admins):
            st.error("An admin with this email already exists.")
            return

        admins.append({"name": name, "email": email})
        _save_admins(admins)
        st.success(f"Admin {name} ({email}) registered. Note: admin list stored in admin_data/admins.json")

# ---------------- Authenticate Admin via OTP ----------------
def authenticate_admin():
    """
    Used in streamlit_app when performing sensitive actions.
    This will send an OTP to the selected admin email and verify it.
    Returns True when verified, False otherwise.
    """
    st.subheader("📧 Admin OTP Verification")

    admins = _load_admins()
    if not admins:
        st.error("No admins registered. Register an admin first.")
        return False

    emails = [a["email"] for a in admins]
    selected = st.selectbox("Select admin email to receive OTP", emails)

    if "otp_sent" not in st.session_state or st.session_state.get("otp_for_email") != selected:
        if st.button("Send OTP"):
            st.session_state.generated_otp = send_otp_to(selected)
            st.session_state.otp_sent = True
            st.session_state.otp_for_email = selected
            st.info(f"OTP sent to {selected}.")
            return False
        return False

    # OTP verify form
    otp_input = st.text_input("Enter the OTP sent to your email", type="password")
    if st.button("Verify OTP for action"):
        if otp_input == st.session_state.get("generated_otp", ""):
            st.success("✅ OTP verified.")
            # clear OTP state for next time
            st.session_state.pop("generated_otp", None)
            st.session_state.pop("otp_sent", None)
            st.session_state.pop("otp_for_email", None)
            return True
        else:
            st.error("❌ Invalid OTP.")
            return False

    return False
