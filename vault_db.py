import streamlit as st
import sqlite3
import base64
import os
import pandas as pd
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ---------------------------------------------------------
# Page Configuration & Dark Cyber Theme Styling
# ---------------------------------------------------------
st.set_page_config(page_title="CryptVault Admin Console", layout="wide")

st.markdown(
    """
    <style>
    .stApp { background-color: #0d1117; }
    h1, h2, h3, p, label, span { color: #c9d1d9 !important; }
    [data-testid="stSidebar"] { background-color: #161b22; }
    div.stButton > button:first-child {
        background-color: #238636; color: white; border: none;
    }
    div.stButton > button:first-child:hover {
        background-color: #2ea043; border: none;
    }
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    </style>
    """,
    unsafe_allow_html=True
)

# ---------------------------------------------------------
# Cryptographic Key Derivation Engine (PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------
SALT_FILE = "vault.salt"


def get_or_create_salt():
    """Generates a persistent 16-byte cryptographic salt if not present."""
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        return salt
    with open(SALT_FILE, "rb") as f:
        return f.read()


def derive_secure_key(passphrase: str, salt: bytes) -> bytes:
    """Derives a cryptographically strong 32-byte key from a user password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,  # Industry baseline for balancing security/speed
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


# Initialize salt and database connections
salt = get_or_create_salt()
conn = sqlite3.connect('vault.db', check_same_thread=False)
c = conn.cursor()

c.execute('''
    CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        label TEXT NOT NULL, 
        encrypted_content BLOB NOT NULL
    )
''')
conn.commit()

# ---------------------------------------------------------
# UI App Logic
# ---------------------------------------------------------
st.title("ADMIN CYBER-VAULT")
st.caption("CryptVault Secure Database & Asset Control panel")

# Sidebar Authentication
master_key_input = st.sidebar.text_input("Enter Admin Master Password", type="password")

if master_key_input:
    try:
        # Derive key securely using the master password and fixed local salt
        derived_key = derive_secure_key(master_key_input, salt)
        cipher = Fernet(derived_key)

        # Access control menu
        menu = ["View Vault", "Add Secret", "Delete Secret", "Backup & Maintenance"]
        choice = st.sidebar.selectbox("Navigation", menu)

        # -------------------------------------------------
        # OPTION 1: VIEW AND DECRYPT SECRETS
        # -------------------------------------------------
        if choice == "View Vault":
            st.subheader("Current Encrypted Assets")
            data = pd.read_sql_query("SELECT * FROM secrets", conn)

            if not data.empty:
                decrypted_list = []
                for _, row in data.iterrows():
                    try:
                        decrypted_val = cipher.decrypt(row['encrypted_content']).decode()
                        decrypted_list.append(
                            {"ID": row['id'], "Asset Label": row['label'], "Secret Content": decrypted_val})
                    except Exception:
                        # Triggers if the wrong password was entered but bypassed validation, or data is corrupt
                        decrypted_list.append({"ID": row['id'], "Asset Label": row['label'],
                                               "Secret Content": "DECRYPTION FAILURE (Invalid Key)"})

                st.dataframe(pd.DataFrame(decrypted_list), use_container_width=True)
            else:
                st.info("The vault database is currently empty.")

        # -------------------------------------------------
        # OPTION 2: ADD NEW SECRET
        # -------------------------------------------------
        elif choice == "Add Secret":
            st.subheader("Store New Secure Asset")
            asset_label = st.text_input("Asset Label / Application Name", placeholder="e.g., GitHub OAuth Token")
            asset_value = st.text_input("Secret Value", type="password", placeholder="Enter sensitive string")

            if st.button("Encrypt & Commit to DB"):
                if asset_label and asset_value:
                    encrypted_text = cipher.encrypt(asset_value.encode())
                    c.execute('INSERT INTO secrets (label, encrypted_content) VALUES (?,?)',
                              (asset_label, encrypted_text))
                    conn.commit()
                    st.success(f"Successfully encrypted and locked configuration for '{asset_label}'.")
                else:
                    st.error("Fields cannot be left blank.")

        # -------------------------------------------------
        # OPTION 3: DELETE SECRET
        # -------------------------------------------------
        elif choice == "Delete Secret":
            st.subheader("Revoke & Delete Asset")
            data = pd.read_sql_query("SELECT id, label FROM secrets", conn)

            if not data.empty:
                st.dataframe(data, use_container_width=True)
                delete_id = st.number_input("Target Record ID to Wipe", min_value=1, step=1)

                if st.button("Permanently Purge Record"):
                    c.execute('DELETE FROM secrets WHERE id=?', (delete_id,))
                    conn.commit()
                    st.warning(f"Record ID {delete_id} dropped from physical database tables.")
                    st.rerun()
            else:
                st.info("No records available to delete.")

        # -------------------------------------------------
        # OPTION 4: BACKUP & EXPORT
        # -------------------------------------------------
        elif choice == "Backup & Maintenance":
            st.subheader("Core Data Archival")

            with open("vault.db", "rb") as db_file:
                st.download_button(
                    label="Download Encrypted vault.db File",
                    data=db_file,
                    file_name="vault_backup.db",
                    mime="application/octet-stream"
                )

            with open(SALT_FILE, "rb") as salt_file:
                st.download_button(
                    label="Download Cryptographic vault.salt File",
                    data=salt_file,
                    file_name="vault.salt",
                    mime="application/octet-stream"
                )
            st.caption(
                "Warning Note: To restore backups on a different machine, you need BOTH the vault database file and the specific .salt file generated during creation.")

    except Exception as e:
        st.sidebar.error(f"Cryptographic subsystem error: {str(e)}")

else:
    st.warning("Access Denied. Provide the Master Password in the sidebar panel to mount the encrypted volumes.")