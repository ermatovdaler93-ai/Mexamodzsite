import argparse, secrets, sqlite3, hashlib
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent
DB = ROOT / "mexxa.db"

def main():
    p = argparse.ArgumentParser(description="Generate MEXXA MODZ access key")
    p.add_argument("--days", type=int, default=1, help="Validity in days (1, 7, 30, etc.)")
    p.add_argument("--note", default="", help="Admin note")
    args = p.parse_args()
    if args.days < 1 or args.days > 3650:
        raise SystemExit("days must be between 1 and 3650")
    key = "MEXXA-" + "-".join(secrets.token_hex(2).upper() for _ in range(3))
    digest = hashlib.sha256(key.encode()).hexdigest()
    con = sqlite3.connect(DB)
    con.execute("""INSERT INTO keys(key_hash,key_hint,duration_seconds,created_at,note)
                   VALUES(?,?,?,?,?)""",
                (digest, key[-4:], args.days * 86400, int(datetime.now().timestamp()), args.note[:120]))
    con.commit()
    con.close()
    print("\nНовый KEY (показывается только сейчас):")
    print(key)
    print(f"Срок: {args.days} дн.\n")
if __name__ == "__main__":
    main()
