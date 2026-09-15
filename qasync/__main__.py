from pathlib import Path

from .envfile import load_dotenv

load_dotenv(Path.cwd() / ".env")

from .app import main

main()
