#!/usr/bin/env python3
import asyncio
import datetime
import os
import requests
from dataclasses import dataclass, field
from database import db
from pprint import pprint
from twitchbot import TwitchBot, ChatMessage, Token, Permission


TWITCH_CLIENT_ID = os.environ.get("TWITCH_CLIENT_ID", "")
TWITCH_SECRET = os.environ.get("TWITCH_SECRET", "")
TWITCH_CHANNEL = os.environ.get("TWITCH_CHANNEL", "")
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


class PosmBot(TwitchBot):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.posm_reply_timer = Timer(10)

    async def posm_post_worker(self):
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
            while True:
                try:
                    await self.send(
                        TWITCH_CHANNEL,
                        f"New possum just dropped! {possum_url} (via: @PossumEveryHour)"
                    )
                    break
                except asyncio.CancelledError:
                    return
                except:
                    print("[!] @PossumEveryHour send failed")
                    await asyncio.sleep(5)

    async def on_token_refresh(self, token: Token):
        await super().on_token_refresh(token)
        db.base64_token = token.to_b64()
        db.save()

    async def on_chat_message(self, message: ChatMessage):
        await super().on_chat_message(message)

        # Check for periodic :V
        lower_text = message.text.lower()
        if "posm" in lower_text and self.posm_reply_timer.ready:
            await self.send(message.channel, ":V")

    async def yee_command(self, message: ChatMessage):
        await self.send(message.channel, "rebeck6YEE")


async def main():
    print("[!] Starting PosmBot")

    bot: PosmBot = await PosmBot.create(TWITCH_CLIENT_ID, TWITCH_SECRET, Token.from_b64(db.base64_token))
    await bot.join(TWITCH_CHANNEL)
    bot.add_task('posm_post', bot.posm_post_worker())
    bot.register_command('yee', bot.yee_command, Permission.MODERATOR)

    await bot.run()


if __name__ == '__main__':
    asyncio.run(main())
