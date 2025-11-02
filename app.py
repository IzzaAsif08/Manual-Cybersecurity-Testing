import streamlit as st
from pymongo import MongoClient
from datetime import datetime
import os

# ================================
#  APP CONFIGURATION
# ================================
st.set_page_config(page_title="FinTech Luxe", layout="centered")

st.title("💸 FinTech Luxe App")
st.caption("Secure FinTech app with MongoDB Atlas backend")

# ================================
#  MONGO CONNECTION
# ================================

# Try to get Mongo URI from Streamlit Secrets first, fallback to env/local
MONGO_URI = (
    st.secrets.get("MONGODB_URI")
    if "MONGODB_URI" in st.secrets
    else os.getenv(
        "MONGODB_URI",
        "mongodb+srv://izzaasifbaloch101_db_user:IEK0zPQSIWAVPqhQ@cluster0.wer7jtb.mongodb.net/fintech_db?retryWrites=true&w=majority"
    )
)

try:
    client = MongoClient(MONGO_URI)
    db = client["fintech_db"]
    users = db["users"]

    st.sidebar.success("✅ Connected to MongoDB Atlas")
except Exception as e:
    st.sidebar.error(f"❌ MongoDB Connection Failed: {e}")

# ================================
#  TEST CONNECTION BLOCK (optional)
# ================================
with st.expander("🔍 Test MongoDB Connection"):
    if st.button("Insert Test Document"):
        test_doc = {
            "username": "test_user",
            "timestamp": datetime.utcnow()
        }
        users.insert_one(test_doc)
        st.success("✅ Test document inserted successfully!")
    if st.button("Show Latest Document"):
        doc = users.find_one(sort=[("_id", -1)])
        st.json(doc)

# ================================
#  SIMPLE LOGIN/REGISTER SYSTEM
# ================================
st.header("🔐 User Authentication")

menu = st.radio("Select Option", ["Register", "Login"])

if menu == "Register":
    st.subheader("📝 Create an Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        if users.find_one({"username": username}):
            st.warning("⚠️ Username already exists.")
        else:
            users.insert_one({"username": username, "password": password, "created_at": datetime.utcnow()})
            st.success("✅ Registration successful!")

elif menu == "Login":
    st.subheader("🔑 Login to Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user = users.find_one({"username": username, "password": password})
        if user:
            st.success(f"🎉 Welcome, {username}!")
        else:
            st.error("❌ Invalid credentials. Try again.")

# ================================
#  FOOTER
# ================================
st.markdown("---")
st.caption("Developed securely with ❤️ — FinTech Luxe by [Your Team Name]")
