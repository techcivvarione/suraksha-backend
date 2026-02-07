import io
from PIL import Image
import pytesseract


class OCRException(Exception):
    """Raised when OCR processing fails"""
    pass


def extract_text_from_image(image_bytes: bytes) -> str:
    """
    Extract text from image bytes using OCR.

    This function is SAFE:
    - If OCR fails → raises OCRException
    - Does NOT crash FastAPI
    """

    try:
        image = Image.open(io.BytesIO(image_bytes))
    except Exception:
        raise OCRException("Invalid image file")

    try:
        text = pytesseract.image_to_string(image)
        text = text.strip()

        if not text:
            raise OCRException("No readable text found in image")

        return text

    except OCRException:
        raise
    except Exception:
        raise OCRException("OCR processing failed")
