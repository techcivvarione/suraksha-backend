"""worker_runner.py — legacy entry point, no longer needed.

The async scan job worker has been removed. Image scanning is now handled
synchronously by POST /scan/image with no background worker required.
"""
import sys

if __name__ == "__main__":
    print(
        "The scan worker is no longer required.\n"
        "Image scanning is now synchronous via POST /scan/image.\n"
        "Start the API with: uvicorn app.main:app --reload"
    )
    sys.exit(0)
