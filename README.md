# Overview

PosmBot grabs the latest tweet from https://botsin.space/@possumeveryhour every hour and sends it in a twitch chat. It was written for my personal use, but feel free to use or derive the code any way you like. (See LICENSE)

# How To Run

- Copy example.env to .env
- Create a twitch developer account, and save the client id and client secret into .env
- Set the app redirect URI to http://localhost:3000
- Put a twitch channel into .env (the channel name is the broadcaster's name)
- Run `docker-compose build`
- Run ./src/generate_token.py (you'll need to `pip install dotenv`)
- Copy the base64 token that is printed to the terminal
- Paste the base64 token into this command `./admin.sh <your base64 token>`
- Run `docker-compose up -d`
- Check `docker-compose logs` to make sure it connected properly

# Notes

- Everything was tested on linux, your mileage may vary on other OS's (some paths may need to change, like /var/posmbot)
- The mastodon environment variables are not being used currently, since @PossumEveryHour is public
- Email me if you have any questions, posmbot@miramontes.dev
