from dotenv import load_dotenv
from imagekitio import ImageKit
import os

load_dotenv()

# Initialize ImageKit with only private_key
imagekit = ImageKit(
    private_key=os.getenv("IMAGEKIT_PRIVATE_KEY")
)

# Store URL endpoint for reuse
URL_ENDPOINT = os.getenv("IMAGEKIT_URL_ENDPOINT")
PUBLIC_KEY = os.getenv("IMAGEKIT_PUBLIC_KEY")