import aiohttp
import asyncio
import json
import random
import requests
import secrets
import threading
import traceback
import websockets.client as ws
from base64 import b64encode, b64decode
from dataclasses import dataclass
from enum import Enum
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Set, Tuple, Union
from urllib.parse import urlencode, parse_qs


TWITCH_API_BASE_URL = "https://api.twitch.tv/helix"
TWITCH_AUTH_BASE_URL = "https://id.twitch.tv"
TWITCH_PUB_SUB_URL = "wss://pubsub-edge.twitch.tv"
TWITCH_AUTHORIZE_URL = TWITCH_AUTH_BASE_URL + "/oauth2/authorize"
TWITCH_VALIDATE_URL = TWITCH_AUTH_BASE_URL + "/oauth2/validate"
TWITCH_TOKEN_URL = TWITCH_AUTH_BASE_URL + "/oauth2/token"
TWITCH_IRC_URL = "wss://irc-ws.chat.twitch.tv:443"


class AuthScope(str, Enum):
    ANALYTICS_READ_EXTENSION = 'analytics:read:extensions'
    ANALYTICS_READ_GAMES = 'analytics:read:games'
    BITS_READ = 'bits:read'
    CHANNEL_READ_SUBSCRIPTIONS = 'channel:read:subscriptions'
    CHANNEL_READ_STREAM_KEY = 'channel:read:stream_key'
    CHANNEL_EDIT_COMMERCIAL = 'channel:edit:commercial'
    CHANNEL_READ_HYPE_TRAIN = 'channel:read:hype_train'
    CHANNEL_MANAGE_BROADCAST = 'channel:manage:broadcast'
    CHANNEL_READ_REDEMPTIONS = 'channel:read:redemptions'
    CHANNEL_MANAGE_REDEMPTIONS = 'channel:manage:redemptions'
    CLIPS_EDIT = 'clips:edit'
    USER_EDIT = 'user:edit'
    USER_EDIT_BROADCAST = 'user:edit:broadcast'
    USER_READ_BROADCAST = 'user:read:broadcast'
    USER_READ_EMAIL = 'user:read:email'
    USER_EDIT_FOLLOWS = 'user:edit:follows'
    CHANNEL_MODERATE = 'channel:moderate'
    CHAT_EDIT = 'chat:edit'
    CHAT_READ = 'chat:read'
    WHISPERS_READ = 'whispers:read'
    WHISPERS_EDIT = 'whispers:edit'
    MODERATION_READ = 'moderation:read'
    CHANNEL_SUBSCRIPTIONS = 'channel_subscriptions'
    CHANNEL_READ_EDITORS = 'channel:read:editors'
    CHANNEL_MANAGE_VIDEOS = 'channel:manage:videos'
    USER_READ_BLOCKED_USERS = 'user:read:blocked_users'
    USER_MANAGE_BLOCKED_USERS = 'user:manage:blocked_users'
    USER_READ_SUBSCRIPTIONS = 'user:read:subscriptions'
    USER_READ_FOLLOWS = 'user:read:follows'
    CHANNEL_READ_GOALS = 'channel:read:goals'
    CHANNEL_READ_POLLS = 'channel:read:polls'
    CHANNEL_MANAGE_POLLS = 'channel:manage:polls'
    CHANNEL_READ_PREDICTIONS = 'channel:read:predictions'
    CHANNEL_MANAGE_PREDICTIONS = 'channel:manage:predictions'
    MODERATOR_MANAGE_AUTOMOD = 'moderator:manage:automod'
    CHANNEL_MANAGE_SCHEDULE = 'channel:manage:schedule'
    MODERATOR_MANAGE_CHAT_SETTINGS = 'moderator:manage:chat_settings'
    MODERATOR_MANAGE_BANNED_USERS = 'moderator:manage:banned_users'
    MODERATOR_READ_BLOCKED_TERMS = 'moderator:read:blocked_terms'
    MODERATOR_MANAGE_BLOCKED_TERMS = 'moderator:manage:blocked_terms'
    CHANNEL_MANAGE_RAIDS = 'channel:manage:raids'
    MODERATOR_MANAGE_ANNOUNCEMENTS = 'moderator:manage:announcements'
    MODERATOR_MANAGE_CHAT_MESSAGES = 'moderator:manage:chat_messages'
    USER_MANAGE_CHAT_COLOR = 'user:manage:chat_color'
    CHANNEL_MANAGE_MODERATORS = 'channel:manage:moderators'
    CHANNEL_READ_VIPS = 'channel:read:vips'
    CHANNEL_MANAGE_VIPS = 'channel:manage:vips'
    USER_MANAGE_WHISPERS = 'user:manage:whispers'
    MODERATOR_READ_CHATTERS = 'moderator:read:chatters'


class AuthError(Exception):
    pass


@dataclass
class Token:
    current_value: str
    refresh_value: str = None

    async def refresh(self, client_id: str, client_secret: str):
        if self.refresh_value is None:
            raise AuthError("non-refreshable token")
        params = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_value,
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(TWITCH_TOKEN_URL, data=params) as response:
                if response.status != 200:
                    raise AuthError(f"token refresh attempt received status code {response.status}")
                refresh_data = await response.json()
        self.current_value = refresh_data["access_token"]
        self.refresh_value = refresh_data["refresh_token"]

    def to_json(self) -> str:
        """
        Convert the token to a JSON string for storage.
        """
        return json.dumps({
            "current": self.current_value,
            "refresh": self.refresh_value,
        })

    @classmethod
    def from_json(cls, s: str):
        """
        Deserialize a token that has been converted to JSON.
        """
        data: dict = json.loads(s)
        return cls(
            data.get("current", ""),
            data.get("refresh", None),
        )

    def to_b64(self) -> str:
        return b64encode(self.to_json().encode('utf-8')).decode('ascii')

    @classmethod
    def from_b64(cls, s: str):
        return cls.from_json(b64decode(s).decode('utf-8'))


def generate_authorize_url(client_id: str, redirect_uri: str, scopes: List[AuthScope] = [AuthScope.CHAT_READ, AuthScope.CHAT_EDIT]) -> Tuple[str, str]:
    """
    Returns a URL that a user can click to authorize your app, and the state that was
    used to generate the URL.

    For a chat bot to read messages, you need the chat:read (AuthScope.CHAT_READ) scope,
    and to send messages you need the chat:edit (AuthScope.CHAT_EDIT) scope.
    """
    state = secrets.token_hex(16)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
    }
    return f"{TWITCH_AUTHORIZE_URL}?{urlencode(params)}", state


def resolve_token_from_auth_code(client_id: str, client_secret: str, code: str, redirect_uri: str) -> Token:
    params = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    response = requests.post(TWITCH_TOKEN_URL, data=params)
    if response.status_code != 200:
        raise AuthError(f"authorization attempt received status code {response.status_code}")
    auth_data = response.json()
    return Token(auth_data["access_token"], auth_data["refresh_token"])


class LocalAuthHandler(BaseHTTPRequestHandler):
    RESPONSE = b"""
        <title>Authorization Success</title>
        <p>Authorization successful. You may now close this tab.</p>
    """
    def reply_success(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(self.RESPONSE)))
        self.end_headers()
        self.wfile.write(self.RESPONSE)

    def do_GET(self):
        self.reply_success()
        self.resolve_auth_token()

    def do_POST(self):
        self.reply_success()
        self.resolve_auth_token()

    def resolve_auth_token(self):
        self.server.return_value = self.path
        threading.Thread(target=self.server.shutdown, daemon=True).start()


def authorize_chat_bot(client_id: str, client_secret: str, redirect_uri: str = "http://localhost:3000") -> Token:
    """
    Simple method of getting an auth token on a local device. Opens an http
    listener on localhost and generates an auth URL to open in a browser.
    """
    # Display Auth URL for the user
    auth_url, _ = generate_authorize_url(client_id, redirect_uri)
    print("Authorize URL:", auth_url)
    # Open a server to catch the redirect
    server = HTTPServer(("127.0.0.1", 3000), LocalAuthHandler)
    server.return_value = None
    server.serve_forever()
    # Interpret the return value into a code
    query_params = parse_qs(server.return_value[2:])
    code = query_params["code"]
    return resolve_token_from_auth_code(client_id, client_secret, code, redirect_uri)


@dataclass
class IRCMessage:
    tags: Dict[str,str]
    source: str
    command: str
    parameters: List[str]
    body: str


@dataclass
class ChatMessage:
    irc_message: IRCMessage
    id: str
    text: str
    channel: str
    user: str
    is_broadcaster: bool
    is_mod: bool
    is_subscriber: bool
    is_turbo: bool


class TwitchBot:
    COMMAND_PREFIX = "!"

    def __init__(self, client_id: str, client_secret: str, token: Token):
        self.client_id: str = client_id
        self.client_secret: str = client_secret
        self.token: Token = token
        self.websocket: ws.WebSocketClientProtocol = None
        self.background_tasks: dict[str, asyncio.Task] = {}
        self.nonremovable_tasks: Set[asyncio.Task] = set()
        self.latency: float = None
        self.username: str = None
        self.scopes: List[str] = []
        self.user_id: str = None
        self.channels: Set[str] = set()

    def add_task(self, name: str, coro: Union[asyncio.Task, Any]) -> asyncio.Task:
        """
        Add an awaitable to the list of background tasks under a certain name. Adding
        another task with the same name will cause the first one to be cancelled.
        """
        # Prepare task
        if isinstance(coro, asyncio.Task):
            task = coro
        else:
            task = asyncio.create_task(coro)
        task.set_name(name)
        task.add_done_callback(lambda _: self.remove_task(name))
        # Remove any existing task by that name and add the new one
        self.remove_task(name)
        self.background_tasks[name] = task
        return task

    def add_nonremovable_task(self, coro: Union[asyncio.Task, Any]) -> asyncio.Task:
        """
        Similar to add_task, but the added task is anonymous and cannot be removed
        with remove_task() or close(). This should not be used to add long running
        tasks, because of the possibility of tasks persisting past close().
        """
        if isinstance(coro, asyncio.Task):
            task = coro
        else:
            task = asyncio.create_task(coro)
        task.add_done_callback(self.nonremovable_tasks.discard)
        self.nonremovable_tasks.add(task)
        return task

    def remove_task(self, name: str):
        """
        Remove an awaitable added using add_task. Silently ignores names that are not
        present in the current background tasks.
        """
        task = self.background_tasks.pop(name, None)
        if task is not None:
            task.cancel()

    async def connect(self):
        # Cleanup old ping task
        self.remove_task('ping')
        self.remove_task('dispatch')
        # Cleanup old websocket
        if self.websocket is not None:
            self.websocket.close()
            self.websocket = None
        # Validate oauth token
        headers={"Authorization": f"OAuth {self.token.current_value}"}
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(TWITCH_VALIDATE_URL) as response:
                if response.status == 401:
                    raise AuthError(f"the oauth token is invalid, generate a new one")
                elif response.status != 200:
                    raise Exception(f"validation attempt received status code {response.status}")
                validation_data = await response.json()
        self.username = validation_data["login"]
        self.scopes = validation_data["scopes"]
        self.user_id = validation_data["user_id"]
        print("[!] OAuth token validated.")
        # Try connection
        self.websocket = await ws.connect(TWITCH_IRC_URL)
        print("[!] WebSocket IRC connection established.")
        await self.irc_send('CAP REQ :twitch.tv/membership twitch.tv/tags twitch.tv/commands')
        await self.irc_send(f'PASS oauth:{self.token.current_value}')
        await self.irc_send(f'NICK {self.username}')
        # Add ping and dispatch tasks
        self.add_task('ping', self.ping_worker())
        self.add_task('dispatch', self.dispatch_worker())

    async def join(self, *channels: str, timeout: float = 15.0):
        proper_channels: List[str] = []
        for channel in channels:
            # All twitch channels are lowercase
            channel = channel.lower()
            # Twitch channels start with '#'
            if not channel.startswith("#"):
                channel = f"#{channel}"
            proper_channels.append(channel)
        if not proper_channels:
            raise ValueError("no channels specified to join")
        self.channels.update(proper_channels)
        # A join response will cancel this timeout worker and resolve this result
        join_result = asyncio.Future()
        self.add_task('join', self.timeout_worker(join_result, timeout))
        try:
            await self.irc_send(f"JOIN {','.join(proper_channels)}")
        except:
            self.remove_task('join')
            raise
        await join_result

    @classmethod
    async def create(cls, client_id: str, client_secret: str, token: Token):
        """
        Connect to the twitch server and establish background tasks.

        After creation, run() should be awaited to remain in
        the loop, processing callbacks until close() is called.
        """
        bot = cls(client_id, client_secret, token)
        try:
            await bot.connect()
        except AuthError:
            print("[!] Token invalid or expired, attempting to refresh")
            await token.refresh()
            await bot.connect()
        return bot

    async def run(self):
        """
        Runs indefinitely until the close() function is called.
        """
        try:
            await self.add_task('run', self.sleep_worker())
        except asyncio.CancelledError:
            pass

    def close(self):
        """
        Cancel all tasks and return from run()

        NOTE: Cannot be called from within a background task. Use close_from_task() for that.
        """
        for task in self.background_tasks:
            self.remove_task(task)
        self.websocket.close()

    def close_from_task(self, current_task: str):
        """
        Same as close, but can be called by a background task without cancelling itself.
        """
        for task in self.background_tasks:
            if task == current_task:
                continue
            self.remove_task(task)
        self.websocket.close()

    async def send(self, channel: str, message: str):
        """
        Send a PRIVMSG to the specified channel, causing the bot
        to speak in the chat.
        """
        await self.irc_send("<TODO>")

    async def irc_send(self, message: str):
        """
        Send a raw message to the underlying websocket.

        Note: Not for sending messages in the chat.
        """
        await self.websocket.send(message)

    def parse_tags(self, raw_tags: str) -> Dict[str, str]:
        return {}

    def parse_message(self, raw_message: str) -> IRCMessage:
        index = 0

        # Parse out tags
        if raw_message[index] == '@':
            tags_end_index = raw_message.index(' ', index)
            tags = self.parse_tags(raw_message[index + 1:tags_end_index])
            index = tags_end_index + 1
        else:
            tags = {}

        # Parse out source
        if raw_message[index] == ':':
            source_end_index = raw_message.index(' ', index)
            source = raw_message[index + 1:source_end_index]
            index = source_end_index + 1
        else:
            source = None

        # Parse out command
        try:
            command_end_index = raw_message.index(':', index)
        except ValueError:
            command_end_index = len(raw_message)
        command, *parameters = raw_message[index:command_end_index].split()
        index = command_end_index + 1

        # Parse out parameters (may be an empty string)
        body = raw_message[index:]

        return IRCMessage(tags, source, command, parameters, body)

    ###########################
    # Background Task Workers #
    ###########################

    async def sleep_worker(self):
        while True:
            await asyncio.sleep(3600)

    async def dispatch_worker(self):
        while True:
            # Try to read a packet. If we've disconnected, try to reconnect,
            # but if we're cancelled, do not start any new tasks.
            try:
                packet = await self.websocket.recv()
            except asyncio.CancelledError:
                return
            except:
                print("[!] Error: disconnected during recv(), reconnecting.")
                self.add_task('reconnect', self.reconnect_worker())
                return
            # Skip binary frames
            if not isinstance(packet, str):
                print("[!] Error: received non-text frame!")
                continue
            # Split packet into consituent irc messages
            raw_messages = packet.split("\r\n")
            for raw_message in raw_messages:
                # Skip empty messages, such as after the trailing \r\n
                if not raw_message:
                    continue
                # Parse the message into its constituent parts
                try:
                    irc_message = self.parse_message(raw_message)
                except:
                    print("Failed to parse IRC message:", raw_message)
                    traceback.print_exc()
                    continue
                # Call the appropriate callback in a new, non-removable task. This
                # allows the callback to use close() without worrying about cancelling
                # itself.
                try:
                    callback_task = self.add_nonremovable_task(self.on_irc_message(irc_message))
                    callback_task.set_name("on_irc_message")
                except asyncio.CancelledError:
                    return
                except Exception:
                    print("[!] An exception occured during on_irc_message() callback")
                    traceback.print_exc()

    async def ping_worker(self):
        ping_interval = 55
        ping_jitter = 10
        while True:
            await asyncio.sleep(ping_interval + random.randrange(0, ping_jitter))
            ping_waiter = await self.websocket.ping()
            self.latency = await ping_waiter

    async def reconnect_worker(self):
        wait_interval = 1
        while True:
            print("[!] Connect attempt failed. Trying again in {wait_interval} seconds.")
            await asyncio.sleep(wait_interval)
            try:
                await self.connect()
                await self.join(*self.channels)
                break
            except AuthError:
                print("[!] Token invalid or expired, attempting to refresh")
                try:
                    await self.token.refresh(self.client_id, self.client_secret)
                    continue
                except:
                    self.close_from_task('reconnect')
                    return
            except:
                if self.websocket is not None:
                    self.websocket.close()
                    self.websocket = None
                if wait_interval < 256:
                    wait_interval *= 2

    async def timeout_worker(self, future: asyncio.Future, timeout: float):
        await asyncio.sleep(timeout)
        future.set_exception(TimeoutError)

    ###################
    # Event Callbacks #
    ###################

    async def on_irc_message(self, message: IRCMessage):
        """
        Fires on all IRC messages, not just chat messages. Some examples
        are JOIN, PRIVMSG, and USERSTATE.

        Responsible for triggering all other event callbacks.
        """
        if message.command == "NOTICE" and message.body == "Login authentication failed":
            self.close()
        print("[!] IRC Message", message)

    async def on_channel_message(self, message: ChatMessage):
        """
        Fires when a message is received in a channel that the bot is
        subscribed to by calling bot.join()
        """
        if message.is_broadcaster:
            print(f"[{message.channel}] (BROADCASTER) {message.user}: \"{message.text}\"")
        elif message.is_mod:
            print(f"[{message.channel}] (MOD) {message.user}: \"{message.text}\"")
        elif message.is_subscriber:
            print(f"[{message.channel}] (SUB) {message.user}: \"{message.text}\"")
        else:
            print(f"[{message.channel}] {message.user}: \"{message.text}\"")
