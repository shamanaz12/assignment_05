import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate key for encryption
if "key" not in st.session_state:
    st.session_state.key = Fernet.generate_key()
cipher = Fernet(st.session_state.key)

# In-memory data store
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "login_attempts" not in st.session_state:
    st.session_state.login_attempts = 0

MAX_ATTEMPTS = 3


# ------------------- Functions -------------------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()


def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()


def decrypt_data(encrypted_text, passkey):
    hashed_pass = hash_passkey(passkey)
    for enc_text, record in st.session_state.stored_data.items():
        if record["encrypted_text"] == encrypted_text and record["passkey"] == hashed_pass:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None


# ------------------- Sidebar Navigation -------------------
st.sidebar.title("🔐 Menu")
page = st.sidebar.radio("Go to", ["Home", "Store Data", "Retrieve Data", "Login"])

# ------------------- Pages -------------------

if page == "Home":
    st.title("🏠 Welcome to Secure Data App")
    st.write("Encrypt & store data with a secret passkey. Retrieve it anytime!")

elif page == "Store Data":
    st.title("📂 Store Data")
    data = st.text_area("Enter text to encrypt:")
    passkey = st.text_input("Create Passkey", type="password")

    if st.button("Encrypt & Save"):
        if data and passkey:
            enc = encrypt_data(data)
            st.session_state.stored_data[enc] = {
                "encrypted_text": enc,
                "passkey": hash_passkey(passkey)
            }
            st.success("✅ Data encrypted and stored!")
            st.code(enc, language="text")
        else:
            st.error("⚠️ Please fill all fields.")

elif page == "Retrieve Data":
    st.title("🔍 Retrieve Data")

    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        st.warning("Too many failed attempts. Please reauthorize.")
        st.switch_page("Login") if hasattr(st, "switch_page") else None
        st.session_state.page = "Login"
        st.experimental_rerun()

    encrypted_text = st.text_area("Enter Encrypted Text:")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success(f"✅ Decrypted Text:\n{result}")
            else:
                st.error(f"❌ Wrong passkey! Attempts left: {MAX_ATTEMPTS - st.session_state.failed_attempts}")
        else:
            st.error("Please enter all fields.")

elif page == "Login":
    st.title("🔑 Reauthorization")
    password = st.text_input("Enter Admin Password", type="password")

    if st.button("Login"):
        if password == "admin123":
            st.success("✅ Login successful!")
            st.session_state.failed_attempts = 0
            st.session_state.login_attempts = 0
            st.session_state.page = "Retrieve Data"
            st.experimental_rerun()
        else:
            st.session_state.login_attempts += 1
            if st.session_state.login_attempts >= MAX_ATTEMPTS:
                st.error("❌ App locked. Restart to try again.")
                st.stop()
            else:
                st.error(f"Incorrect password! Attempts left: {MAX_ATTEMPTS - st.session_state.login_attempts}")
