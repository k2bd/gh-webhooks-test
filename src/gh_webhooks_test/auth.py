import hashlib
import hmac
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request, status
from pydantic import BaseModel

from gh_webhooks_test.constants import WEBHOOK_SECRET


class GithubHeaders(BaseModel):
    """
    Headers sent by GitHub
    """

    #: Name of the event that triggered the delivery
    event_name: Optional[str]

    #: A GUID to identify the delivery
    delivery_guid: Optional[str]

    #: This header is sent if the webhook is configured with a secret.
    #: This is the HMAC hex digest of the request body, and is generated using
    #: the SHA-256 hash function and the secret as the HMAC key
    secret_hash: Optional[str]


def get_github_headers(
    x_gitHub_event: Optional[str] = Header(None),
    x_github_delivery: Optional[str] = Header(None),
    x_hub_signature_256: Optional[str] = Header(None),
):
    if x_hub_signature_256:
        x_hub_signature_256 = x_hub_signature_256.strip("sha256=")
    return GithubHeaders(
        event_name=x_gitHub_event,
        delivery_guid=x_github_delivery,
        secret_hash=x_hub_signature_256,
    )


async def auth_with_secret(
    request: Request,
    headers: GithubHeaders = Depends(get_github_headers),
):
    """
    Authenticate the webhook request using the webhook's secret
    """
    if not headers.secret_hash:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing secret hash",
        )

    body = await request.body()
    signature = (
        "sha256="
        + hmac.new(
            WEBHOOK_SECRET.encode("utf-8"),
            msg=body,
            digestmod=hashlib.sha256,
        ).hexdigest()
    )

    if signature.lower() != headers.secret_hash.lower():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid secret hash",
        )
