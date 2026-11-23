import sqlite3
import os

DATABASE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "database",
    "dfir.db"
)


def get_connection():
    connection = sqlite3.connect(DATABASE,timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT UNIQUE NOT NULL,
            case_name TEXT NOT NULL,
            description TEXT,
            investigator TEXT,
            severity TEXT,
            status TEXT DEFAULT 'Open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT UNIQUE NOT NULL,
            case_id TEXT NOT NULL,
            evidence_name TEXT NOT NULL,
            evidence_type TEXT,
            source TEXT,
            original_hash TEXT,
            current_hash TEXT,
            integrity_status TEXT DEFAULT 'Not Verified',
            description TEXT,
            file_path TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        )
    """)

    # Migration for an existing database
    columns = [
        row["name"]
        for row in cursor.execute(
            "PRAGMA table_info(evidence)"
        ).fetchall()
    ]

    if "file_path" not in columns:
        cursor.execute(
            "ALTER TABLE evidence ADD COLUMN file_path TEXT"
        )

    connection.commit()
    connection.close()


if __name__ == "__main__":
    initialize_database()
    print("DFIR-X database initialized successfully.")
