import logging
import os

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from gh_webhooks import GhWebhookEventHandler
from gh_webhooks.types import IssueCommentCreated, IssueCommentEdited, PingEvent

from gh_webhooks_test.auth import GithubHeaders, auth_with_secret, get_github_headers

if os.environ.get("K_SERVICE"):
    import google.cloud.logging

    logging_client = google.cloud.logging.Client()
    logging_client.setup_logging()

logger = logging.getLogger(__name__)

app = FastAPI(dependencies=[Depends(auth_with_secret)])

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


event_handler = GhWebhookEventHandler()


@event_handler.on(PingEvent)
async def handle_ping(event: PingEvent):
    logger.info(f"Ping: {event.zen!r}")


@event_handler.on(IssueCommentCreated)
async def handle_new_issue_comment(event: IssueCommentCreated):
    logger.info(f"Comment created: {event.comment.body!r}")


@event_handler.on(IssueCommentEdited)
async def handle_edited_issue_comment(event: IssueCommentEdited):
    logger.info(f"Comment edited: {event.comment.body!r}")


@app.post("/payload")
async def handle_webhook_payload(
    request: Request,
    headers: GithubHeaders = Depends(get_github_headers),
):
    kind = headers.event_name
    event = await request.json()
    await event_handler.handle_event(event, kind)
