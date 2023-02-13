#!/usr/bin/env python3
"""
Runs inside the container.
Takes a base64 encoded token and stores it in the database.
"""

import argparse
from database import db


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("base64_token", type=str)
    args = parser.parse_args()

    db.base64_token = args.base64_token
    db.save()


if __name__ == '__main__':
    main()
