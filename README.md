# Writara.com
import os
import sqlite3
import hashlib
from cryptography.fernet import Fernet
from PIL import Image
import pytesseract
import magic

# Initialize database
conn = sqlite3.connect("file_organizer.db")
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY,
        original_path TEXT,
        encrypted_path TEXT,
        filename TEXT,
        tags TEXT,
        hash TEXT,
        mime_type TEXT
    )
""")
conn.commit()

# Encryption setup
key = Fernet.generate_key()
cipher = Fernet(key)
with open("encryption_key.key", "wb") as key_file:
    key_file.write(key)  # Save key securely

def compute_file_hash(file_path):
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def extract_metadata(file_path):
    """Extract basic metadata (e.g., text from images/PDFs)."""
    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(file_path)
    tags = [mime_type.split("/")[-1]]  # E.g., "pdf", "jpeg"

    if mime_type.startswith("image"):
        try:
            text = pytesseract.image_to_string(Image.open(file_path))
            tags.extend([word.lower() for word in text.split() if len(word) > 3])
        except Exception:
            pass
    return tags, mime_type

def encrypt_file(file_path, output_dir):
    """Encrypt file and store in output directory."""
    with open(file_path, "rb") as f:
        data = f.read()
    encrypted_data = cipher.encrypt(data)
    filename = os.path.basename(file_path)
    encrypted_path = os.path.join(output_dir, f"{hashlib.md5(filename.encode()).hexdigest()}.enc")
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)
    return encrypted_path

def upload_file(file_path, output_dir="encrypted_files"):
    """Upload and organize a file."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    file_hash = compute_file_hash(file_path)
    tags, mime_type = extract_metadata(file_path)
    encrypted_path = encrypt_file(file_path, output_dir)

    cursor.execute(
        "INSERT INTO files (original_path, encrypted_path, filename, tags, hash, mime_type) VALUES (?, ?, ?, ?, ?, ?)",
        (file_path, encrypted_path, os.path.basename(file_path), ",".join(tags), file_hash, mime_type)
    )
    conn.commit()
    print(f"Uploaded and encrypted: {file_path}")

def search_files(query):
    """Search files by tag or filename."""
    cursor.execute("SELECT filename, tags, original_path FROM files WHERE tags LIKE ? OR filename LIKE ?",
                   (f"%{query}%", f"%{query}%"))
    return cursor.fetchall()

# Example usage
if __name__ == "__main__":
    # Install dependencies: pip install cryptography Pillow pytesseract python-magic
    upload_file("sample.jpg", "encrypted_files")
    results = search_files("image")
    for filename, tags, path in results:
        print(f"Found: {filename} (Tags: {tags})")
