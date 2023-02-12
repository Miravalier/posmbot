import asyncio
import random
import traceback
import websockets.client as ws
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Union


TWITCH_API_BASE_URL = "https://api.twitch.tv/helix"
TWITCH_AUTH_BASE_URL = "https://id.twitch.tv"
TWITCH_PUB_SUB_URL = "wss://pubsub-edge.twitch.tv"
TWITCH_VALIDATE_URL = TWITCH_AUTH_BASE_URL + "/oauth2/validate"
TWITCH_IRC_URL = "wss://irc-ws.chat.twitch.tv:443"


class AuthScope(Enum):
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


@dataclass
class Token:
    current_value: str
    refresh_value: str
    expiration: datetime

    def refresh(self):
        pass


def acquire_token(username: str, client_id: str, scopes: List[AuthScope]) -> Token:
    pass


@dataclass
class IRCMessage:
    tags: Dict[str,str]
    source: str
    command: str
    parameters: List[str]


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
    def __init__(self, username: str, client_id: str, token: Token = None) -> None:
        self.username: str = username
        self.client_id: str = client_id
        self.token: Token = token
        self.websocket: ws.WebSocketClientProtocol = None
        self.background_tasks: dict[str, asyncio.Task] = {}
        self.latency: float = None

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
        # Cleanup old websocket
        if self.websocket is not None:
            self.websocket.close()
            self.websocket = None
        # Try connection
        self.websocket = await ws.connect(TWITCH_IRC_URL)
        print("[!] Connection established.")
        await self.irc_send('CAP REQ :twitch.tv/membership twitch.tv/tags twitch.tv/commands')
        await self.irc_send(f'PASS oauth:{self.token.current}')
        await self.irc_send(f'NICK {self.username}')
        # Add ping task
        self.add_task('ping', self.ping_worker())

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
    async def create(cls, username: str, client_id: str, token: Token = None):
        """
        Connect to the twitch server and establish background tasks.

        After creation, run() should be awaited to remain in
        the loop, processing callbacks until close() is called.
        """
        if token is None:
            token = await acquire_token(username, client_id, (AuthScope.CHAT_READ, AuthScope.CHAT_EDIT))

        bot = cls(username, client_id, token)
        try:
            await bot.connect()
        except:
            bot.add_task('reconnect', bot.reconnect_worker())

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
        """
        for task in self.background_tasks:
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
            tags = self.parse_tags(raw_message[index + 1, tags_end_index])
            index = tags_end_index + 1
        else:
            tags = {}

        # Parse out source
        if raw_message[index] == ':':
            source_end_index = raw_message.index(' ', index)
            source = raw_message[index + 1, source_end_index]
            index = source_end_index + 1
        else:
            source = None

        # Parse out command
        try:
            command_end_index = raw_message.index(':', index)
        except ValueError:
            command_end_index = len(raw_message)
        command = raw_message[index:command_end_index]
        index = command_end_index + 1

        # Parse out parameters (may be an empty string)
        parameters = raw_message[index:]

        return IRCMessage(tags, source, command, parameters)

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
                    continue
                # Call the appropriate callback. If it fails
                try:
                    await self.on_irc_message(irc_message)
                except asyncio.CancelledError:
                    return
                except Exception:
                    print("[!] An exception occured during on_irc_message() callback")
                    traceback.print_exc()
                    pass

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
            time_to_sleep = wait_interval + random.randrange(0, 5)
            print("[!] Connect attempt failed. Trying again in {time_to_sleep} seconds.")
            await asyncio.sleep(time_to_sleep)
            try:
                await self.connect()
                return
            except:
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
