# Overview

PosmBot grabs the latest tweet from https://twitter.com/possumeveryhour every hour and sends it in a twitch chat. It was written for my personal use, but feel free to use or derive the code any way you like. (See LICENSE)

# How To Run

- Copy example.env to .env
- Create a twitch developer account, and save the client id and client secret into .env
- Create a twitter developer account, and save the api key, api key secret, and bearer token into .env
- Put a twitch channel into .env (all lowercase)
- Run `docker-compose build`
- Run ./generate_token.py (you'll need to `pip install` twitchAPI and dotenv)
- Copy the refresh token is printed to the terminal
- Paste the refresh token to run `./admin.sh <your refresh token>`
- Run `docker-compose up -d`
- Check `docker-compose logs` to make sure it connected properly

# Notes

- Everything was tested on linux, your mileage may vary on other OS's (some paths may need to change, like /var/posmbot)
- Email me if you have any questions, posmbot@miramontes.dev
