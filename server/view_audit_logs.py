# quick log viewer for testing
import hashlib
from audit_logger import AuditLogger


AUDIT_LOG_FILE = "data/audit.log"


def build_audit_log_key() -> bytes:
    secret = "secure_audit_log_key_2026"
    return hashlib.sha256(secret.encode("utf-8")).digest()


if __name__ == "__main__":
    audit_key = build_audit_log_key()
    logger = AuditLogger(AUDIT_LOG_FILE, audit_key)

    logs = logger.read_decrypted_logs()

    print("Decrypted Audit Log Entries:")
    for entry in logs:
        print(entry)