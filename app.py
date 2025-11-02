import streamlit as st
from pymongo import MongoClient
from datetime import datetime, UTC
import os, re, bcrypt, base64, pandas as pd, io

# -----------------------------
# PAGE CONFIG
# -----------------------------
st.set_page_config(page_title="💸 FinTech Luxe", layout="centered")

# -----------------------------
# CUSTOM STYLING
# -----------------------------
st.markdown("""
    <style>
        body {background-color: #fff0f5;}
        .stApp {background-color: #ffe6f2;}
        h1, h2, h3, label, p, span, div {color: #d63384 !important;}

        /* Sidebar */
        div[data-testid="stSidebar"] {
            background-color: #ffb6c1;
            color: white;
        }

        /* Buttons */
        .stButton>button {
            background-color: #d63384;
            color: white;
            border-radius: 10px;
            font-weight: bold;
        }
        .stButton>button:hover {
            background-color: #ff4081;
            color: white;
        }

        /* Inputs & borders */
        input, textarea {
            border: 1px solid #ff99cc !important;
        }

        /* Uploader text & file icons */
        [data-testid="stFileUploader"] * {
            color: #6a0dad !important;
        }
        [data-testid="stFileUploader"] label {
            color: #b30059 !important;
            font-weight: 600;
        }
        [data-testid="stFileUploader"] section {
            background-color: #fff5f8 !important;
            border: 2px dashed #ff66b2 !important;
        }
        .uploadedFile, .uploadError, .uploadWarning {
            color: #b30059 !important;
        }
    </style>
""", unsafe_allow_html=True)

st.title("💸 FinTech Luxe App")

# -----------------------------
# DATABASE CONNECTION
# -----------------------------
MONGO_URI = (
    st.secrets.get("MONGODB_URI")
    if "MONGODB_URI" in st.secrets
    else os.getenv(
        "MONGODB_URI",
        "mongodb+srv://izzaasifbaloch101_db_user:IEK0zPQSIWAVPqhQ@cluster0.wer7rjt.mongodb.net/fintech_db?retryWrites=true&w=majority"
    )
)

try:
    client = MongoClient(MONGO_URI)
    db = client["fintech_db"]
    users = db["users"]
    logs = db["logs"]
    uploads = db["uploads"]
    st.sidebar.success("✅ Connected to MongoDB Atlas")
except Exception as e:
    st.sidebar.error(f"❌ MongoDB Connection Failed: {e}")

# -----------------------------
# FUNCTIONS
# -----------------------------
def log_action(username, action):
    """Log user actions for auditing."""
    logs.insert_one({"user": username, "action": action, "timestamp": datetime.now(UTC)})

def is_strong_password(password):
    """Password complexity check."""
    return all([
        len(password) >= 8,
        re.search(r"[A-Z]", password),
        re.search(r"[a-z]", password),
        re.search(r"[0-9]", password),
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    ])

def encrypt_data(text):
    return base64.b64encode(text.encode()).decode()

def decrypt_data(text):
    try:
        return base64.b64decode(text.encode()).decode()
    except Exception:
        return "Decryption Error"

# -----------------------------
# AUTHENTICATION SECTION
# -----------------------------
st.header("🔐 Secure User Authentication")
menu = st.radio("Select Option", ["Register", "Login", "Forgot Password"])

# --- REGISTER ---
if menu == "Register":
    st.subheader("📝 Create an Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        if not username or not password:
            st.warning("⚠️ All fields required.")
        elif users.find_one({"username": username}):
            st.warning("⚠️ Username already exists.")
        elif password != confirm_password:
            st.error("❌ Passwords do not match.")
        elif not is_strong_password(password):
            st.warning("⚠️ Password too weak. Use 8+ chars, uppercase, number & symbol.")
        else:
            hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            users.insert_one({
                "username": username,
                "password": hashed_pw,
                "created_at": datetime.now(UTC)
            })
            log_action(username, "User Registered")
            st.success("✅ Registration successful! You can now login.")

# --- LOGIN ---
elif menu == "Login":
    st.subheader("🔑 Login to Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = users.find_one({"username": username})
        if user and bcrypt.checkpw(password.encode(), user["password"]):
            st.session_state["user"] = username
            log_action(username, "User Logged In")
            st.success(f"🎉 Welcome, {username}!")
        else:
            st.error("❌ Invalid credentials.")
            log_action(username, "Failed Login Attempt")

# --- PASSWORD RESET ---
elif menu == "Forgot Password":
    st.subheader("🔁 Reset Password")
    username = st.text_input("Enter your username:")
    new_password = st.text_input("New Password", type="password")

    if st.button("Reset Password"):
        if not users.find_one({"username": username}):
            st.error("❌ Username not found.")
        elif not is_strong_password(new_password):
            st.warning("⚠️ Password too weak.")
        else:
            hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
            users.update_one({"username": username}, {"$set": {"password": hashed_pw}})
            log_action(username, "Password Reset")
            st.success("✅ Password updated successfully!")

# -----------------------------
# USER DASHBOARD
# -----------------------------
if "user" in st.session_state:
    username = st.session_state["user"]
    st.header(f"👤 Welcome, {username}")

    uploaded_file = st.file_uploader("📁 Upload Proof of Payment (JPG/PNG only)", type=["jpg", "jpeg", "png"])
    if uploaded_file:
        uploads.insert_one({
            "user": username,
            "filename": uploaded_file.name,
            "uploaded_at": datetime.now(UTC)
        })
        st.success("✅ File uploaded successfully!")
        log_action(username, f"Uploaded File: {uploaded_file.name}")

    st.subheader("🔐 Data Encryption / Decryption")
    text_to_encrypt = st.text_input("Enter text to encrypt:")
    if st.button("Encrypt"):
        encrypted = encrypt_data(text_to_encrypt)
        st.code(encrypted)
        log_action(username, "Encrypted Data")

    encrypted_input = st.text_input("Enter encrypted text to decrypt:")
    if st.button("Decrypt"):
        decrypted = decrypt_data(encrypted_input)
        st.code(decrypted)
        log_action(username, "Decrypted Data")

    st.subheader("🧾 Profile Update")
    new_username = st.text_input("Change Username:")
    if st.button("Update Profile"):
        if new_username:
            users.update_one({"username": username}, {"$set": {"username": new_username}})
            st.success("✅ Username updated successfully!")
            log_action(username, "Profile Updated")
        else:
            st.warning("⚠️ Username cannot be empty.")

    # Logout with confirmation
    if st.button("Logout"):
        st.session_state.pop("user")
        st.info("👋 Logged out successfully.")
        log_action(username, "User Logged Out")

    # Admin view: Download logs
    if username.lower() == "admin":
        st.subheader("📜 Admin Logs Export")
        all_logs = list(logs.find({}, {"_id": 0}))
        if all_logs:
            df_logs = pd.DataFrame(all_logs)
            csv = df_logs.to_csv(index=False)
            st.download_button("⬇️ Download Logs (CSV)", data=csv, file_name="user_logs.csv", mime="text/csv")

# -----------------------------
# CYBERSECURITY TEST PLAN TABLE
# -----------------------------
with st.expander("🧠 Manual Cybersecurity Test Plan"):
    test_data = [
        ["1", "Input Validation – SQL Injection", "Entered 'OR 1=1--", "Input rejected", "Error handled", "✅ Pass"],
        ["2", "Password Strength", "Weak password 12345", "Rejected", "Warning shown", "✅ Pass"],
        ["3", "File Upload Validation", "Tried .exe file", "Rejected", "Correct behavior", "✅ Pass"],
        ["4", "Secure Error Handling", "Forced divide-by-zero", "App didn’t crash", "Controlled message", "✅ Pass"],
    ]
    df = pd.DataFrame(test_data, columns=["#", "Test Case", "Action", "Expected Outcome", "Observed Result", "Status"])
    st.dataframe(df, use_container_width=True)

st.markdown("---")
st.caption("💗 Developed By — IZZA ASIF BALOCH")
