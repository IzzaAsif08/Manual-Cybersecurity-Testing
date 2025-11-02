import os
import time
import re
import streamlit as st
import bcrypt
from cryptography.fernet import Fernet
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# 💖 PAGE CONFIG
st.set_page_config(
    page_title="FinTech Luxe 💎",
    page_icon="💖",
    layout="wide",
)

# 🌈 CUSTOM PINK THEME CSS
st.markdown("""
    <style>
    /* Background Gradient */
    body {
        background: linear-gradient(120deg, #ffdde1 0%, #ee9ca7 100%);
        color: #2c2c2c;
        font-family: 'Poppins', sans-serif;
    }

    /* Glassmorphism card effect */
    .block-container {
        background: rgba(255, 255, 255, 0.8);
        border-radius: 30px;
        box-shadow: 0 8px 32px rgba(255, 105, 180, 0.3);
        backdrop-filter: blur(10px);
        padding: 3rem 4rem;
    }

    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #ffb6c1 0%, #ffc0cb 100%);
        border-right: 2px solid #ff99b8;
    }

    /* Headers */
    h1, h2, h3 {
        color: #c2185b;
        text-align: center;
        font-weight: 700;
        letter-spacing: 1px;
    }

    /* Buttons */
    .stButton>button {
        background: linear-gradient(90deg, #ff66a3, #ff85c1);
        color: white;
        font-weight: 600;
        padding: 0.7rem 1.6rem;
        border-radius: 12px;
        border: none;
        box-shadow: 0 0 10px rgba(255, 20, 147, 0.3);
        transition: 0.3s ease;
    }
    .stButton>button:hover {
        background: linear-gradient(90deg, #ff99cc, #ff66a3);
        transform: scale(1.05);
        box-shadow: 0 0 20px rgba(255, 20, 147, 0.5);
    }

    /* Text inputs */
    .stTextInput>div>div>input, textarea, .stNumberInput input {
        border-radius: 10px;
        border: 2px solid #ffb6c1;
        background-color: #fff0f5;
        padding: 0.4rem;
    }

    /* Cards */
    .action-card {
        background: rgba(255, 255, 255, 0.6);
        border-radius: 20px;
        box-shadow: 0 6px 18px rgba(255, 192, 203, 0.5);
        padding: 2rem;
        text-align: center;
        transition: 0.3s ease;
        cursor: pointer;
    }
    .action-card:hover {
        transform: translateY(-5px);
        background: rgba(255, 240, 245, 0.9);
    }

    /* Messages */
    .stSuccess, .stWarning, .stError {
        border-radius: 12px !important;
        font-weight: 600;
    }

    /* Footer */
    footer {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)

# 🛡 SECURITY SETTINGS
KEY_FILE = "secret.key"
LOCKOUT_LIMIT = 5
LOCKOUT_TIME = 300
SESSION_TIMEOUT = 600

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return open(KEY_FILE, "rb").read()

fernet = Fernet(load_key())

# 💾 MONGO CONFIG
MONGO_USER = "abdulsamadsaleem1208_db_user"
MONGO_CLUSTER = "cluster0.qkvquvb.mongodb.net"
MONGO_DBNAME = "fintech_db"

def get_mongo_password():
    try:
        if "MONGODB_PASSWORD" in st.secrets:
            return st.secrets["MONGODB_PASSWORD"]
    except Exception:
        pass
    return os.getenv("MONGODB_PASSWORD")

MONGO_PWD = get_mongo_password()
if not MONGO_PWD:
    st.error("🔒 MongoDB password not found. Configure in secrets or environment.")
    st.stop()

MONGO_URI = f"mongodb+srv://{MONGO_USER}:{MONGO_PWD}@{MONGO_CLUSTER}/{MONGO_DBNAME}?retryWrites=true&w=majority"

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=8000)
    client.admin.command("ping")
    st.sidebar.success("💗 Connected to MongoDB Atlas")
except ConnectionFailure:
    st.sidebar.error("⚠️ Connection failed. Check Atlas IP access.")
    st.stop()

db = client[MONGO_DBNAME]
users_col = db["users"]
audit_col = db["audit_log"]
pred_col = db["predictions"]

# 💬 HELPERS
def log_action(username, action):
    try:
        audit_col.insert_one({
            "username": username,
            "action": action,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })
    except:
        pass

def valid_input(text, max_len=100):
    if not text or len(text) > max_len or re.search(r"[<>{}'\";]|--|\bOR\b|\bAND\b", text, re.IGNORECASE):
        return False
    return True

def is_logged_in():
    return st.session_state.get("logged_in", False)

def check_session_timeout():
    if "last_activity" in st.session_state:
        if time.time() - st.session_state["last_activity"] > SESSION_TIMEOUT:
            logout()
            st.warning("⏰ Session expired. Please log in again.")
            st.rerun()
    st.session_state["last_activity"] = time.time()

def logout():
    for k in list(st.session_state.keys()):
        del st.session_state[k]

# 🌷 REGISTER
def register():
    st.header("🌸 Create Your Account")
    col1, col2 = st.columns(2)
    with col1:
        username = st.text_input("👤 Username", max_chars=50)
        email = st.text_input("📧 Email", max_chars=100)
    with col2:
        password = st.text_input("🔑 Password", type="password")
        confirm = st.text_input("💖 Confirm Password", type="password")

    if st.button("✨ Register Now"):
        if not valid_input(username, 50):
            st.warning("Invalid username.")
            return
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            st.warning("Invalid email address.")
            return
        if password != confirm:
            st.warning("Passwords do not match.")
            return
        if len(password) < 8 or not re.search(r"(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*\\W)", password):
            st.warning("Password too weak.")
            return

        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        if users_col.find_one({"username": username}) or users_col.find_one({"email": email}):
            st.error("Username or email already exists.")
            return

        users_col.insert_one({
            "username": username,
            "email": email,
            "password": hashed_pw,
            "failed_attempts": 0,
            "lockout_until": 0,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        })
        log_action(username, "User Registered")
        st.success("🌷 Registration successful! Please log in.")

# 💞 LOGIN
def login():
    st.header("💞 Welcome Back")
    st.markdown("Enter your secure credentials below 👇")

    username = st.text_input("👤 Username")
    password = st.text_input("🔑 Password", type="password")

    if st.button("💫 Login"):
        user = users_col.find_one({"username": username})
        if not user:
            st.error("Invalid credentials.")
            return

        hashed_pw = user.get("password")
        failed_attempts = user.get("failed_attempts", 0)
        lockout_until = user.get("lockout_until", 0)
        now = time.time()

        if lockout_until and lockout_until > now:
            st.error("🚫 Account locked temporarily.")
            return

        if isinstance(hashed_pw, str):
            hashed_pw = hashed_pw.encode("utf-8")

        if bcrypt.checkpw(password.encode("utf-8"), hashed_pw):
            users_col.update_one({"username": username}, {"$set": {"failed_attempts": 0, "lockout_until": 0}})
            st.session_state["logged_in"] = True
            st.session_state["username"] = username
            st.session_state["last_activity"] = time.time()
            log_action(username, "User Logged In")
            st.success("💖 Login successful!")
            st.rerun()
        else:
            fa = failed_attempts + 1
            update_data = {"failed_attempts": fa}
            if fa >= LOCKOUT_LIMIT:
                update_data["lockout_until"] = now + LOCKOUT_TIME
                st.error("💥 Too many failed attempts. Locked temporarily.")
                log_action(username, "Account Locked")
            else:
                st.error(f"Wrong password. {LOCKOUT_LIMIT - fa} attempts left.")
            users_col.update_one({"username": username}, {"$set": update_data})

# 💎 DASHBOARD
def dashboard():
    check_session_timeout()
    st.header(f"💼 Welcome, {st.session_state.get('username')} 💕")
    st.caption("Your luxury FinTech control center ✨")

    cols = st.columns(3)
    features = [
        ("🧾 View Profile", update_profile),
        ("🔮 Add Prediction", add_prediction),
        ("🔐 Encrypt / Decrypt", encryption_demo),
        ("📂 Upload File", upload_file),
        ("📜 View Logs", show_logs),
        ("🚪 Logout", lambda: logout_and_exit())
    ]

    for i, (label, func) in enumerate(features):
        with cols[i % 3]:
            if st.button(label, key=f"btn_{i}"):
                func()

def logout_and_exit():
    log_action(st.session_state.get("username"), "User Logged Out")
    logout()
    st.info("💔 Logged out successfully.")
    st.rerun()

def update_profile():
    st.subheader("💌 Update Profile Info")
    new_email = st.text_input("Enter new email")
    if st.button("💫 Update"):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
            st.warning("Invalid email format.")
        else:
            users_col.update_one({"username": st.session_state.get("username")}, {"$set": {"email": new_email}})
            log_action(st.session_state.get("username"), "Email Updated")
            st.success("✅ Email updated!")

def add_prediction():
    st.subheader("🔮 Save Prediction")
    text = st.text_input("Prediction text")
    val = st.number_input("Score", value=0.0, step=0.1)
    if st.button("💾 Save Prediction"):
        pred_col.insert_one({
            "username": st.session_state.get("username"),
            "text": text,
            "score": float(val),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        })
        log_action(st.session_state.get("username"), "Prediction Saved")
        st.success("🌸 Saved successfully!")

def encryption_demo():
    st.subheader("🔐 Encryption / Decryption")
    data = st.text_input("Enter text to encrypt")
    if st.button("Encrypt"):
        encrypted = fernet.encrypt(data.encode()).decode()
        st.session_state["enc"] = encrypted
        st.code(encrypted)
    if st.button("Decrypt"):
        if "enc" in st.session_state:
            st.code(fernet.decrypt(st.session_state["enc"].encode()).decode())

def upload_file():
    st.subheader("📂 Upload File")
    file = st.file_uploader("Choose a file (.csv, .txt, .pdf)", type=["csv", "txt", "pdf"])
    if file:
        st.success(f"✅ Uploaded: {file.name}")
        log_action(st.session_state.get("username"), f"Uploaded {file.name}")

def show_logs():
    st.subheader("📜 Activity Logs")
    for log in audit_col.find().sort("_id", -1).limit(50):
        st.text(f"{log.get('timestamp')} | {log.get('username')} | {log.get('action')}")

# MAIN ENTRY
def main():
    st.title("💖 FinTech Luxe Dashboard")
    menu = ["Login", "Register", "About"]
    choice = st.sidebar.selectbox("🌷 Menu", menu)

    if choice == "Login":
        if is_logged_in():
            dashboard()
        else:
            login()
    elif choice == "Register":
        register()
    elif choice == "About":
        st.info("""
        🌸 **FinTech Luxe App**
        - Pink Glassmorphism Design 💎  
        - MongoDB Atlas Backend 🌍  
        - Full Encryption & Security 🔐  
        - Lockout, Timeout & Logging 🛡  
        - Designed by ChatGPT ✨  
        """)

if __name__ == "__main__":
    main()
