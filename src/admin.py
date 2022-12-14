#!/usr/bin/env python3
import argparse
from database import db


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("twitch_refresh_token", type=str)
    args = parser.parse_args()

    db.twitch_refresh_token = args.twitch_refresh_token
    db.save()


if __name__ == '__main__':
    main()
