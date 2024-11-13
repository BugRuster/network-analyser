import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    MAX_THREADS = 3
    SCAN_TIMEOUT = 300  # 5 minutes
    DEFAULT_PORT_RANGE = '1-1024'
    ALLOWED_SCAN_TYPES = ['basic', 'service', 'vulnerability']