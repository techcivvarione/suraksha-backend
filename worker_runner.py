import logging

from app.workers.scan_worker import ScanWorker


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)


if __name__ == "__main__":
    ScanWorker().run_forever()
