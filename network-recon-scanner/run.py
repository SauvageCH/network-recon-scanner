"""Launch the web app:  python run.py"""
from app import create_app
from config import Config

if __name__ == "__main__":
    # Bound to localhost on purpose: do not expose this tool to a network.
    create_app().run(host=Config.HOST, port=Config.PORT, debug=False)
