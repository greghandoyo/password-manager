import secrets
from argon2.low_level import hash_secret_raw, Type
import os
import getpass
import sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def derive_key(master_password, salt):
    return hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )

def create_vault(master_password):
    salt = secrets.token_bytes(16)

    key = derive_key(master_password, salt)

    verification_message = b"vault-verification-v1"

    nonce, ciphertext = encrypt_password(
        verification_message.decode(),
        key
    )

    connection = sqlite3.connect("passwords.db")
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO vault_metadata (
            id, salt, time_cost, memory_cost,
            parallelism, hash_len,
            verification_nonce, verification_ciphertext
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        1,
        salt,
        3,
        65536,
        4,
        32,
        nonce,
        ciphertext
    ))

    connection.commit()
    connection.close()

    print("Vault created successfully!")

def unlock_vault(master_password):
    connection = sqlite3.connect("passwords.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT salt, time_cost, memory_cost, parallelism, hash_len,
               verification_nonce, verification_ciphertext
        FROM vault_metadata
        WHERE id = 1
    """)

    metadata = cursor.fetchone()
    connection.close()

    if metadata is None:
        print("No vault found.")
        return None

    # Extract saved metadata
    salt, time_cost, memory_cost, parallelism, hash_len, verification_nonce, verification_ciphertext = metadata

    # Recreate encryption key
    key = hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID
    )

    # Verify master password
    try:
        verification_message = AESGCM(key).decrypt(
            verification_nonce,
            verification_ciphertext,
            None
        )

        if verification_message == b"vault-verification-v1":
            print("Vault unlocked successfully!")
            return key

        print("Verification failed.")
        return None

    except InvalidTag:
        print("Incorrect master password.")
        return None
    
def vault_exists():
    connection = sqlite3.connect("passwords.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id FROM vault_metadata
        WHERE id = 1
    """)

    result = cursor.fetchone()
    connection.close()

    return result is not None

def main():
    create_database()

    if vault_exists():
        print("\nWelcome back!")
        master_password = getpass.getpass("Enter master password: ")

        key = unlock_vault(master_password)

        if key is None:
            return

    else:
        print("\nWelcome! Let's create your password vault.")
        master_password = getpass.getpass("Create a master password: ")

        create_vault(master_password)
        key = unlock_vault(master_password)

    while True:
        print("\n--- Password Manager ---")
        print("1. Add a credential")
        print("2. Exit")
        print("3. Inspect database")
        print("4. View a credential")

        choice = input("Choose an option: ")

        if choice == "1":
            add_credential(key)

        elif choice == "2":
            print("Locking your vault. Goodbye!")
            break

        elif choice == "3":
            inspect_database()

        elif choice == "4":
            view_credential(key)

        else:
            print("Invalid option. Please try again.")
    

    
def encrypt_password(password, key):
    # Create an AES-GCM encryption object
    aesgcm = AESGCM(key)

    # Generate a unique 12-byte nonce
    nonce = os.urandom(12)

    # Convert password into bytes
    password_bytes = password.encode()

    # Encrypt the password
    ciphertext = aesgcm.encrypt(nonce, password_bytes, None)

    return nonce, ciphertext

def decrypt_password(nonce, ciphertext, key):
    # Recreate the AES-GCM object
    aesgcm = AESGCM(key)

    # Decrypt and authenticate the ciphertext
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    # Convert bytes back into readable text
    return plaintext.decode()

def create_database():
    # Connect to the database (creates it if it doesn't exist)
    connection = sqlite3.connect("passwords.db")

    # Create a cursor to execute SQL commands
    cursor = connection.cursor()

    # Create the credentials table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL
        )
    """)

    # Table 2: Stores vault configuration and verification data
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault_metadata (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            time_cost INTEGER NOT NULL,
            memory_cost INTEGER NOT NULL,
            parallelism INTEGER NOT NULL,
            hash_len INTEGER NOT NULL,
            verification_nonce BLOB NOT NULL,
            verification_ciphertext BLOB NOT NULL
        )
    """)

    # Save changes
    connection.commit()

    # Close the connection
    connection.close()

def save_credential(website, username, password, key):
    # Encrypt the password first
    nonce, ciphertext = encrypt_password(password, key)

    # Connect to the database
    connection = sqlite3.connect("passwords.db")
    cursor = connection.cursor()

    # Insert the encrypted credential
    cursor.execute("""
        INSERT INTO credentials (website, username, nonce, ciphertext)
        VALUES (?, ?, ?, ?)
    """, (website, username, nonce, ciphertext))

    # Save and close
    connection.commit()
    connection.close()

    print("Credential saved successfully!")

def add_credential(key):
    website = input("Enter website: ").strip()
    username = input("Enter username: ").strip()
    password = getpass.getpass("Enter password to save: ")

    if not website or not username or not password:
        print("All fields are required.")
        return

    save_credential(website, username, password, key)

def view_credential(key):
    website = input("Enter website to search: ").strip()

    result = get_credential(website, key)

    if result:
        username, password = result

        print("\n--- Retrieved Credential ---")
        print("Website:", website)
        print("Username:", username)
        print("Password:", password)

def inspect_database():
    connection = sqlite3.connect("passwords.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT website, username, nonce, ciphertext
        FROM credentials
    """)

    records = cursor.fetchall()

    for record in records:
        print("Website:", record[0])
        print("Username:", record[1])
        print("Nonce:", record[2].hex())
        print("Ciphertext:", record[3].hex())

    connection.close()

def get_credential(website, key):
    connection = sqlite3.connect("passwords.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT username, nonce, ciphertext
        FROM credentials
        WHERE website = ?
        ORDER BY id DESC
        LIMIT 1
    """, (website,))

    record = cursor.fetchone()
    connection.close()

    if record is None:
        print("Credential not found.")
        return None

    username, nonce, ciphertext = record

    password = decrypt_password(nonce, ciphertext, key)

    return username, password

if __name__ == "__main__":
    main()