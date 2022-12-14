#!/usr/bin/env python3
import asyncio
import os
from dotenv import load_dotenv
from twitchAPI import Twitch
from twitchAPI.oauth import UserAuthenticator
from twitchAPI.types import AuthScope


load_dotenv()


TWITCH_CLIENT_ID = os.environ.get("TWITCH_CLIENT_ID", "")
TWITCH_SECRET = os.environ.get("TWITCH_SECRET", "")
TWITCH_USER_SCOPE = [AuthScope.CHAT_READ, AuthScope.CHAT_EDIT]


async def main():
    twitch = await Twitch(TWITCH_CLIENT_ID, TWITCH_SECRET)
    auth = UserAuthenticator(twitch, TWITCH_USER_SCOPE)
    token, refresh_token = await auth.authenticate()
    print("Token:", token)
    print("Refresh Token:", refresh_token)


if __name__ == '__main__':
    asyncio.run(main())
