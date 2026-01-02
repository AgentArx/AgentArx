"""Run AgentArx Web UI as a module"""

from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path.cwd() / ".env"
if env_path.exists():
    load_dotenv(env_path)
    print(f"✓ Loaded environment from: {env_path}")
else:
    print(f"⚠ No .env file found at: {env_path}")
    print("  Please create a .env file with your OPENAI_API_KEY")

from .app import run_server

if __name__ == '__main__':
    run_server()
