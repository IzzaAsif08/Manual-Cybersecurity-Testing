# 💼 Secure FinTech App – Manual Cybersecurity Testing (Streamlit + MongoDB)

## 🧩 Overview
This project is a **Secure FinTech Web Application** built using **Streamlit** and **MongoDB Atlas**.  
It demonstrates **secure development practices** combined with **manual cybersecurity testing** to evaluate and strengthen the app’s defenses against common web vulnerabilities.

The app covers:
- Secure authentication (hashed passwords)
- Input sanitization
- Encryption for sensitive data
- Secure file uploads
- Error handling and validation
- Session management
- Manual cybersecurity testing for 20 scenarios

---

## 🚀 Live App
🔗 **Streamlit App:** [https://secure-fintech-app.streamlit.app](#)  
💻 **GitHub Repository:** [https://github.com/abdulsamadxyz/manual-cybersecurity-testing](#)

🧑‍🏫 **Guidance by:** [Dr. Usama Arshad](#)

---

## ⚙️ Features
- **User Registration & Login**
- **Encrypted Data Storage**
- **MongoDB Atlas Integration**
- **Session Management & Logout**
- **Secure Error Handling**
- **File Upload Validation**
- **Input & Length Validation**
- **Account Lockout after failed logins**
- **Audit Logging (user actions tracked)**

---

## 🔒 Manual Cybersecurity Testing

| No | Test Case | Action | Expected Outcome | Result |
|----|------------|---------|------------------|---------|
| 1 | SQL Injection | Enter `' OR 1=1--` in login | Error handled | ✅ Pass |
| 2 | Password Strength | Use weak password `12345` | Rejected | ✅ Pass |
| 3 | Special Characters | Add `<script>` in username | Escaped/Sanitized | ✅ Pass |
| 4 | Unauthorized Access | Access dashboard w/out login | Redirected to login | ✅ Pass |
| 5 | Session Expiry | Idle for 10 mins | Auto logout | ✅ Pass |
| 6 | Logout Functionality | Press logout | Session cleared | ✅ Pass |
| 7 | Data Confidentiality | View DB file | Encrypted values | ✅ Pass |
| 8 | File Upload Validation | Upload `.exe` | Rejected | ✅ Pass |
| 9 | Error Message Leakage | Trigger DB error | Generic message | ✅ Pass |
| 10 | Input Length Validation | Enter 5000 chars | Rejected | ✅ Pass |
| 11 | Duplicate Registration | Reuse username | Blocked | ✅ Pass |
| 12 | Numeric Field Validation | Input letters | Validation error | ✅ Pass |
| 13 | Password Match | Mismatch confirm password | Blocked | ✅ Pass |
| 14 | Unauthorized Modification | Change transaction ID | Denied | ✅ Pass |
| 15 | Email Validation | Enter `abc@` | Rejected | ✅ Pass |
| 16 | Login Lockout | 5 failed logins | Account locked | ✅ Pass |
| 17 | Secure Error Handling | Divide-by-zero | App didn’t crash | ✅ Pass |
| 18 | Encrypted Record Check | DB unreadable outside app | Secure | ✅ Pass |
| 19 | Input Encoding | Enter emoji | Handled gracefully | ✅ Pass |
| 20 | Empty Fields | Submit empty form | Warning shown | ✅ Pass |

---

## 🧠 Manual Test Example – Encrypted Record Check
1. Register user with password: **Bank123**  
2. View DB in MongoDB Atlas → password shown as encrypted (`gAAAAA...==`)  
3. Try decrypting outside app → **fails**  
4. App correctly decrypts internally  
✅ **Pass – Data protected in storage**

---

## 🛠️ Tech Stack
- **Frontend:** Streamlit
- **Backend:** Python
- **Database:** MongoDB Atlas
- **Encryption:** `cryptography.fernet`
- **Password Hashing:** `bcrypt`
- **Session Handling:** Streamlit Session State

---

## 🧩 Folder Structure
