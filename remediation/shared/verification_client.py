import requests

from .config import (
    VERIFICATION_TOKEN,
    VERIFICATION_TIMEOUT,
    VERIFICATION_URL,
)


def verify(payload):

    if not VERIFICATION_URL:
        raise RuntimeError(
            "VERIFICATION_URL is not configured"
        )

    if not VERIFICATION_TOKEN:
        raise RuntimeError(
            "VERIFICATION_TOKEN is not configured"
        )

    headers = {
        "Content-Type": "application/json",
        "Authorization": (
            "Bearer "
            + VERIFICATION_TOKEN
        ),
    }

    response = requests.post(
        VERIFICATION_URL,
        json=payload,
        headers=headers,
        timeout=VERIFICATION_TIMEOUT,
    )

    response.raise_for_status()

    return response.json()
