
import sqlite3
from config import Config

def migrate():
    print(f"Migrating database at {Config.DATABASE_PATH}...")
    conn = sqlite3.connect(Config.DATABASE_PATH)
    try:
        # Check if tags column exists
        cursor = conn.execute("PRAGMA table_info(alerts)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'tags' not in columns:
            print("Adding 'tags' column to 'alerts' table...")
            conn.execute("ALTER TABLE alerts ADD COLUMN tags TEXT")
            print("Migration successful.")
        else:
            print("'tags' column already exists.")
            
    except Exception as e:
        print(f"Migration failed: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate()
