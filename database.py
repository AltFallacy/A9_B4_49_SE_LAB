"""
database.py - Database Connection and Helper Module
---------------------------------------------------
This module manages the SQLite3 database connection, schema creation,
and core database operations for the Sports Management System (SPMS).

Design Principles:
1. Parameterized Queries: All SQL queries use '?' placeholders to prevent SQL Injection.
2. sqlite3.Row Factory: Returns rows that can be accessed by column name (like dicts).
3. Defensive Constraints: Tables use SQLite CHECK constraints for data integrity.
"""

import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

# Default database filename, can be overridden via environment variable
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, os.environ.get("DATABASE_PATH", "spms.db"))

SCHEMA_SQL = """
-- Table 1: Users table for staff and administrator authentication
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table 2: Equipment inventory table
CREATE TABLE IF NOT EXISTS equipment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    quantity INTEGER NOT NULL CHECK (quantity >= 0),
    condition TEXT NOT NULL CHECK (condition IN ('Good', 'Needs Repair', 'Damaged')),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


def get_db_path(db_path=None):
    """
    Returns the resolved absolute path to the SQLite database.
    Allows passing a custom path (e.g. for isolated test suites).
    """
    if db_path is not None:
        return db_path
    return os.path.join(BASE_DIR, os.environ.get("DATABASE_PATH", "spms.db"))


def get_db_connection(db_path=None):
    """
    Establishes and returns a connection to the SQLite database.
    Configures row_factory so query results can be indexed by column name.
    """
    resolved_path = get_db_path(db_path)
    conn = sqlite3.connect(resolved_path)
    # Enable access to columns by name: row['name'], row['quantity']
    conn.row_factory = sqlite3.Row
    # Ensure foreign keys and pragma rules are active
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path=None):
    """
    Initializes database tables according to SCHEMA_SQL.
    Safe to run multiple times (uses CREATE TABLE IF NOT EXISTS).
    """
    conn = get_db_connection(db_path)
    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()


def create_user(username, password, db_path=None):
    """
    Creates a new user record with a Werkzeug PBKDF2:SHA256 password hash.
    Returns (True, user_id) on success, or (False, error_message) on failure.
    """
    cleaned_username = username.strip() if username else ""
    if not cleaned_username or len(cleaned_username) < 3:
        return False, "Username must be at least 3 characters long."

    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters long."

    # Generate cryptographic hash (salted PBKDF2 with SHA-256)
    password_hash = generate_password_hash(password)

    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (cleaned_username, password_hash),
        )
        conn.commit()
        return True, cursor.lastrowid
    except sqlite3.IntegrityError:
        return False, f"User '{cleaned_username}' already exists."
    finally:
        conn.close()


def verify_user(username, password, db_path=None):
    """
    Verifies user credentials against the SQLite database.
    Returns the user Row if valid, or None if invalid.
    """
    if not username or not password:
        return None

    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username.strip(),),
        )
        user = cursor.fetchone()

        if user and check_password_hash(user["password_hash"], password):
            return user
        return None
    finally:
        conn.close()
