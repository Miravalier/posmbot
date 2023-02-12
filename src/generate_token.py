#!/usr/bin/env python3
"""
Runs outside of the container, generates a b64 encoded token
and prints it to the terminal.
"""

import os
import twitchbot
from dotenv import load_dotenv



load_dotenv()


TWITCH_CLIENT_ID = os.environ.get("TWITCH_CLIENT_ID", "")
TWITCH_SECRET = os.environ.get("TWITCH_SECRET", "")


def main():
    token = twitchbot.authorize_chat_bot(TWITCH_CLIENT_ID, TWITCH_SECRET)
    print("Token:", token.to_b64())


if __name__ == '__main__':
    main()
