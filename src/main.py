#!/usr/bin/env python3
import asyncio
import datetime
import os
import requests
from dataclasses import dataclass, field
from database import db
from functools import partial
from pprint import pprint
from twitchAPI import Twitch
from twitchAPI.oauth import refresh_access_token
from twitchAPI.types import AuthScope, ChatEvent
from twitchAPI.chat import Chat, EventData, ChatMessage, ChatSub

ADMINS = [admin.strip().lower() for admin in os.environ.get("ADMINS").split(",")]
TWITCH_CLIENT_ID = os.environ.get("TWITCH_CLIENT_ID", "")
TWITCH_SECRET = os.environ.get("TWITCH_SECRET", "")
TWITCH_CHANNEL = os.environ.get("TWITCH_CHANNEL", "")
TWITCH_USER_SCOPE = [AuthScope.CHAT_READ, AuthScope.CHAT_EDIT]

MASTODON_URL = "https://botsin.space"
POSSUM_EVERY_HOUR_USER_ID = 109536299782193051


@dataclass
class Timer:
    interval: int = 10 # In seconds
    last_event: datetime = field(default_factory=datetime.datetime.now)

    @property
    def ready(self):
        now = datetime.datetime.now()
        if now > self.last_event + datetime.timedelta(seconds=10):
            self.last_event = now
            return True
        else:
            return False


def mastodon_auth(r):
    r.headers["User-Agent"] = "PythonBot"
    return r


def search_mastodon_user_id(username: str):
    search_url = MASTODON_URL + "/api/v2/search?q={}"

    response = requests.get(search_url.format(username))
    if response.status_code != 200:
        print(response.status_code, response.content)
    else:
        pprint(response.json())


def get_newest_possum() -> str:
    statuses_url = MASTODON_URL + "/api/v1/accounts/{id}/statuses"

    query_params = {"only_media": True, "limit": 1}
    if db.most_recent_status_id:
        query_params["since_id"] = db.most_recent_status_id

    response = requests.get(
        statuses_url.format(id=POSSUM_EVERY_HOUR_USER_ID),
        params=query_params,
        auth=mastodon_auth,
    )

    if response.status_code != 200:
        print("API Error:", response.content)
        return None

    statuses = response.json()
    if len(statuses) == 0:
        return None
    status = statuses[0]
    newest_image_url = status["media_attachments"][0]["url"]

    db.most_recent_status_id = status["id"]
    db.save()
    return newest_image_url


async def main(ready_event: asyncio.Event, chat: Chat):
    # Wait for on_ready to trigger
    print("[!] Waiting for on_ready event")
    await ready_event.wait()

    # Enter main loop
    print("[!] Entering main loop")
    while True:
        # Sleep until just past the hour
        current_time = datetime.datetime.now()
        minutes_to_wait = 60 - current_time.minute
        seconds_to_wait = (minutes_to_wait * 60) + 3
        await asyncio.sleep(seconds_to_wait)
        # Get the newest possum image
        while (possum_url := get_newest_possum()) is None:
            await asyncio.sleep(300)
        # Send a chat message
        await chat.send_message(
            TWITCH_CHANNEL,
            f"New possum just dropped! {possum_url} (via: @PossumEveryHour)"
        )


async def on_ready(ready_event: asyncio.Event, loop: asyncio.AbstractEventLoop, event_data: EventData):
    print(f'[!] Twitch Bot ready to join channel(s) {TWITCH_CHANNEL}')
    await event_data.chat.join_room(TWITCH_CHANNEL)
    print(f'[!] Channels joined successfully')
    loop.call_soon_threadsafe(ready_event.set)


posm_reply_timer = Timer(10)

async def on_message(msg: ChatMessage):
    if msg is None:
        return

    if msg.user is not None:
        user = msg.user.name
    else:
        user = "<None>"

    if msg.text:
        text = msg.text
    else:
        text = ""

    print(f'[Msg] User "{user}" said: "{text}"')

    lower_text = text.lower()

    # Check for ! commands
    if user in ADMINS:
        if lower_text.startswith("!posmtest"):
            await msg.chat.send_message(TWITCH_CHANNEL, "rebeck6YEE")
            return

    # Check for periodic :V
    if ("posm" in lower_text or "possum" in lower_text) and posm_reply_timer.ready:
        await msg.chat.send_message(TWITCH_CHANNEL, ":V")
        return


async def on_sub(sub: ChatSub):
    print(f'[Sub] In channel')


async def setup():
    print("[!] Beginning setup")
    # Set up chat client
    twitch = await Twitch(TWITCH_CLIENT_ID, TWITCH_SECRET)
    token, refresh_token = await refresh_access_token(db.twitch_refresh_token, TWITCH_CLIENT_ID, TWITCH_SECRET)
    db.twitch_refresh_token = refresh_token
    db.save()
    await twitch.set_user_authentication(token, TWITCH_USER_SCOPE, db.twitch_refresh_token)
    chat = await Chat(twitch)
    print("[!] User authentication set")

    # Register event handlers
    ready_event = asyncio.Event()
    chat.register_event(ChatEvent.READY, partial(on_ready, ready_event, asyncio.get_running_loop()))
    chat.register_event(ChatEvent.MESSAGE, on_message)
    chat.register_event(ChatEvent.SUB, on_sub)

    # Start the chat bot
    chat.start()

    # Run the main loop
    try:
        await asyncio.create_task(main(ready_event, chat))
    finally:
        chat.stop()
        await twitch.close()


if __name__ == '__main__':
    asyncio.run(setup())
