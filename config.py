# API Configuration
API_KEY = "ghostintheshellgenerate"
OBFUSCATED_PATH = "/x7y9z2"  # Obfuscated endpoint path

# C2 Endpoints Configuration
C2_ENDPOINTS = [
    ("ghostintheshellredteam.com", 4444),
    ("ghostintheshellredteam.com", 9000),
    ("ghostintheshellredteam.com", 1337),
    ("66.228.62.178", 4444),
    ("66.228.62.178", 9000),
    ("66.228.62.178", 1337)
]

# Security Settings
MAX_PAYLOAD_SIZE = 1024 * 1024  # 1MB max payload size
REQUEST_TIMEOUT = 30  # seconds
MAX_REQUESTS_PER_MINUTE = 60

# Logging Configuration
LOG_LEVEL = "INFO"
LOG_FILE = "metabash.log" 