from enum import Enum


class ScanType(str, Enum):
    PASSWORD = "PASSWORD"
    EMAIL = "EMAIL"
    QR = "QR"
    THREAT = "THREAT"
    REALITY_IMAGE = "REALITY_IMAGE"
    REALITY_VIDEO = "REALITY_VIDEO"
    REALITY_AUDIO = "REALITY_AUDIO"
