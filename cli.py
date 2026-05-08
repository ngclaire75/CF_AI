"""CyberINK — CLI removed.

All scanning and agent functionality is now available through the web dashboard.

To start the dashboard:
    python -m uvicorn dashboard.api_fast:app --host 0.0.0.0 --port 8893

Then open http://localhost:8893 in your browser.
"""
import sys

def main():
    print(
        "\n  CyberINK CLI has been removed.\n"
        "\n"
        "  All scanning is now done through the web dashboard.\n"
        "  Start the server with:\n"
        "\n"
        "      python -m uvicorn dashboard.api_fast:app --host 0.0.0.0 --port 8893\n"
        "\n"
        "  Then open http://localhost:8893\n"
    )
    sys.exit(0)

if __name__ == '__main__':
    main()
