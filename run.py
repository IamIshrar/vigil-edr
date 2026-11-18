"""Start Vigil EDR.

    python run.py            start the agent and open the dashboard
    python run.py --no-browser

For full visibility (Security log, every process's connections, firewall
actions), run it from a terminal opened with "Run as administrator".
"""
import argparse
import logging
import sys
import threading
import time
import webbrowser

from vigil import __version__
from vigil.agent import Agent
from vigil.config import CONFIG, IS_WINDOWS
from vigil.web import create_app

BANNER = r"""
 __     ___       _ _   _____ ____  ____
 \ \   / (_) __ _(_) | | ____|  _ \|  _ \
  \ \ / /| |/ _` | | | |  _| | | | | |_) |
   \ V / | | (_| | | | | |___| |_| |  _ <
    \_/  |_|\__, |_|_| |_____|____/|_| \_\
            |___/          v{v}
"""


def main():
    parser = argparse.ArgumentParser(description="Vigil EDR")
    parser.add_argument("--no-browser", action="store_true", help="do not open the dashboard automatically")
    args = parser.parse_args()

    print(BANNER.format(v=__version__))
    if not IS_WINDOWS:
        print("Note: Vigil is built for Windows. On this OS the process, network and file\n"
              "collectors work; persistence, event log and firewall features are disabled.\n")

    agent = Agent()
    if not agent.admin:
        print("Running without Administrator rights: the Security event log, some processes'\n"
              "details and firewall actions will be unavailable. Right-click your terminal and\n"
              "choose 'Run as administrator' for full coverage.\n")
    agent.start()

    url = f"http://{CONFIG['host']}:{CONFIG['port']}"
    print(f"Dashboard: {url}")
    print(f"Rules loaded: {len(agent.engine.rules)}  |  Press Ctrl+C to stop.\n")
    if not args.no_browser:
        threading.Thread(target=lambda: (time.sleep(1.5), webbrowser.open(url)), daemon=True).start()

    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app = create_app(agent)
    try:
        app.run(host=CONFIG["host"], port=CONFIG["port"], threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        pass
    print("Vigil stopped.")
    sys.exit(0)


if __name__ == "__main__":
    main()
