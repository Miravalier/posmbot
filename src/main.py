#!/usr/bin/env python3
import asyncio
import datetime
import os
import requests
from database import db
from functools import partial
from twitchAPI import Twitch
from twitchAPI.oauth import refresh_access_token
from twitchAPI.types import AuthScope, ChatEvent
from twitchAPI.chat import Chat, EventData, ChatMessage, ChatSub


TWITCH_CLIENT_ID = os.environ.get("TWITCH_CLIENT_ID", "")
TWITCH_SECRET = os.environ.get("TWITCH_SECRET", "")
TWITCH_CHANNEL = os.environ.get("TWITCH_CHANNEL", "")
TWITCH_USER_SCOPE = [AuthScope.CHAT_READ, AuthScope.CHAT_EDIT]

TWITTER_BEARER_TOKEN = os.environ.get("TWITTER_BEARER_TOKEN", "")
TWEETS_URL = "https://api.twitter.com/2/users/{id}/tweets"
POSSUM_EVERY_HOUR_USER_ID = 1022089486849765376


def twitter_auth(r):
    r.headers["Authorization"] = f"Bearer {TWITTER_BEARER_TOKEN}"
    r.headers["User-Agent"] = "PythonMiravalierBot"
    return r


def get_newest_possum() -> str:
    query_params = {
            "exclude": "retweets,replies",
            "expansions": "attachments.media_keys",
            "media.fields": "url",
    }
    if db.most_recent_tweet_id:
        query_params["since_id"] = db.most_recent_tweet_id

    response = requests.get(
        TWEETS_URL.format(id=POSSUM_EVERY_HOUR_USER_ID),
        params=query_params,
        auth=twitter_auth,
    ).json()

    if response.get('meta', {}).get("result_count", 0) == 0:
        return None

    image_urls_by_media_key = {
        item["media_key"]: item["url"]
        for item in response.get("includes", {}).get("media", [])
        if item["type"] == "photo"
    }
    if len(image_urls_by_media_key) == 0:
        return None

    tweets_with_images = [
        item for item in response["data"]
        if (media_keys := item.get("attachments", {}).get("media_keys", []))
        and media_keys[0] in image_urls_by_media_key
    ]
    newest_tweet_with_image = max(
        tweets_with_images,
        key=lambda item: int(item["id"])
    )
    db.most_recent_tweet_id = newest_tweet_with_image["id"]
    newest_image_url = image_urls_by_media_key[newest_tweet_with_image["attachments"]["media_keys"][0]]
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


last_message_time = datetime.datetime.now()

async def on_message(msg: ChatMessage):
    global last_message_time
    print(f'[Msg] In channel "{msg.room.name}", user "{msg.user.name}" said: "{msg.text}"')
    text = msg.text.lower()
    current_time = datetime.datetime.now()
    if ("posm" in text or "possum" in text) and current_time > last_message_time + datetime.timedelta(seconds=10):
        await msg.chat.send_message(TWITCH_CHANNEL, ":V")
        last_message_time = current_time


async def on_sub(sub: ChatSub):
    print(f'[Sub] In channel {sub.room.name}, Type: {sub.sub_plan}, Message: {sub.sub_message}')


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
