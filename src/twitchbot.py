import aiohttp
import asyncio
import functools
import inspect
import json
import random
import requests
import secrets
import shlex
import threading
import traceback
import websockets.client as ws
from base64 import b64encode, b64decode
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum, IntEnum
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Callable, Dict, List, Set, Tuple, Union
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


class Permission(IntEnum):
    PUBLIC = 0
    SUBSCRIBER = 1
    VIP = 2
    MODERATOR = 3
    BROADCASTER = 4


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


def validate_channel(channel: str) -> str:
    # All twitch channels are lowercase
    channel = channel.lower()
    # Twitch channels start with '#'
    if not channel.startswith("#"):
        channel = f"#{channel}"
    return channel


@dataclass
class Command:
    callback: Callable[..., None]
    parameters: List[inspect.Parameter]
    permission: Permission


@dataclass
class IRCMessage:
    tags: Dict[str,str]
    source: str
    command: str
    parameters: List[str]
    body: str


@dataclass
class ChatMessage:
    id: str
    text: str
    channel: str
    user_id: str
    user_name: str
    is_broadcaster: bool
    is_mod: bool
    is_vip: bool
    is_subscriber: bool
    is_staff: bool
    is_first_message: bool
    is_whisper: bool
    color: str
    timestamp: int
    type: str = "message"

    @property
    def permission(self):
        if self.is_broadcaster:
            return Permission.BROADCASTER
        elif self.is_mod:
            return Permission.MODERATOR
        elif self.is_vip:
            return Permission.VIP
        elif self.is_subscriber:
            return Permission.SUBSCRIBER
        else:
            return Permission.PUBLIC

    def to_json(self) -> str:
        return json.dumps({k: v for k, v in asdict(self).items() if v is not None})


class TwitchBot:
    log_irc = False
    log_chat = True
    command_prefix = "!"

    def __init__(self, client_id: str, client_secret: str, token: Token):
        self.client_id: str = client_id
        self.client_secret: str = client_secret
        self.token: Token = token
        self.websocket: ws.WebSocketClientProtocol = None
        self.background_tasks: dict[str, asyncio.Task] = {}
        self.nonremovable_tasks: Set[asyncio.Task] = set()
        self.waiting_futures: dict[str, asyncio.Future] = {}
        self.latency: float = None
        self.username: str = None
        self.scopes: List[str] = []
        self.user_id: str = None
        self.channels: Set[str] = set()
        self.registered_commands: dict[str, Command] = {}

    def register_command(self, command: str, callback: Callable[..., None], permission: Permission = Permission.PUBLIC):
        # Parse parameters from the callback signature
        parameters = []
        signature = inspect.signature(callback, follow_wrapped=True)
        for _, parameter in signature.parameters.items():
            # Validate only positionals are present
            if parameter.kind == parameter.KEYWORD_ONLY:
                raise TypeError("keyword-only parameters are not allowed on commands")
            elif parameter.kind == parameter.VAR_POSITIONAL:
                raise TypeError("*args parameters are not allowed on commands")
            elif parameter.kind == parameter.VAR_KEYWORD:
                raise TypeError("**kwargs parameters are not allowed on commands")
            parameters.append(parameter)
        # If the callback is non-async, wrap it in an executor
        if inspect.iscoroutinefunction(callback):
            command_callback = callback
        else:
            @functools.wraps(callback)
            async def async_executor_wrapper(*args):
                return await asyncio.get_running_loop().run_in_executor(
                    None, functools.partial(callback, *args))
            command_callback = async_executor_wrapper
        # Put the actual values into the registered commands dict
        self.registered_commands[command] = Command(command_callback, parameters, permission)

    def add_task(self, name: str, coro: Union[asyncio.Task, Any]) -> asyncio.Task:
        """
        Add a coro or task to the dict of background tasks under a certain name. Adding
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
        Remove a coro or task added using add_task. Silently ignores names that do
        not exist or have already been removed.
        """
        task = self.background_tasks.pop(name, None)
        if task is not None and not task.done():
            task.cancel()

    def add_future(self, name: str):
        """
        Adds an awaitable future to the collection reachable from other callbacks under
        the given name.
        """
        # Prep new future
        future = asyncio.Future()
        # Remove any existing future by that name and add the new one
        self.remove_future(name)
        self.waiting_futures[name] = future
        return future

    def resolve_future(self, name: str, result: Any = None):
        """
        Finishes the future by returning the given result. Silently ignores names that do
        not exist or have already been resolved or removed.
        """
        future = self.waiting_futures.get(name, None)
        if future is not None and not future.done():
            future.set_result(result)

    def remove_future(self, name: str):
        """
        Finishes the future by raising an asyncio.CancelledError, and removes it from the
        collection. Silently ignores names that do not exist or have already been resolved
        or removed.
        """
        future = self.waiting_futures.pop(name, None)
        if future is not None and not future.done():
            future.set_exception(asyncio.CancelledError("cancelled due to removal"))

    async def wait_for_future(self, name: str, timeout: float):
        future = self.waiting_futures[name]
        try:
            return await asyncio.wait_for(future, timeout)
        finally:
            self.remove_future(name)

    async def validate_token(self):
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

    async def connect(self, timeout: float = 15.0):
        """
        Used internally during create() and the reconnect() handler.

        Call create() instead of calling connect() directly.
        """
        # Validate oauth token
        await self.validate_token()
        print("[!] OAuth token validated.")
        # Try connection
        self.websocket = await ws.connect(TWITCH_IRC_URL)
        print("[!] WebSocket IRC connection established.")
        await self.irc_send('CAP REQ :twitch.tv/membership twitch.tv/tags twitch.tv/commands')
        await self.irc_send(f'PASS oauth:{self.token.current_value}')
        await self.irc_send(f'NICK {self.username}')
        # Start a timeout, waiting for the auth success message
        self.add_future('auth')
        # Add ping and dispatch tasks, the dispatch task will trigger the
        # auth future's completion.
        self.add_task('ping', self.ping_worker())
        self.add_task('dispatch', self.dispatch_worker())
        self.add_task('validate_token', self.validate_token_worker())
        # Wait for the auth success or timeout, whichever is first
        await self.wait_for_future('auth', timeout)

    async def join(self, *channels: str, timeout: float = 15.0):
        """
        Joins any number of twitch channels to begin receiving callbacks
        related to those channels.
        """
        proper_channels: List[str] = []
        for channel in channels:
            proper_channels.append(validate_channel(channel))
        if not proper_channels:
            raise ValueError("no channels specified to join")
        self.channels.update(proper_channels)
        # Send a JOIN request to the server, if it fails don't bother
        # waiting for the join_result
        self.add_future('join')
        try:
            await self.irc_send(f"JOIN {','.join(proper_channels)}")
        except:
            self.remove_future('join')
            raise
        # Wait for the join success or timeout, whichever is first
        await self.wait_for_future('join', timeout)

    @classmethod
    async def create(cls, client_id: str, client_secret: str, token: Token, timeout: float = 15.0):
        """
        Connect to the twitch server and establish background tasks.

        After creation, run() should be awaited to remain in
        the loop, processing callbacks until close() is called.
        """
        bot = cls(client_id, client_secret, token)
        try:
            await bot.connect(timeout)
        except AuthError:
            print("[!] Token invalid or expired, attempting to refresh")
            await token.refresh(client_id, client_secret)
            await bot.on_token_refresh(token)
            await bot.connect(timeout)
        return bot

    async def run(self):
        """
        Runs indefinitely until the close() function is called.
        """
        try:
            await self.add_task('run', self.sleep_worker())
        except asyncio.CancelledError:
            pass

    async def close(self):
        """
        Cancel all tasks and return from run()

        NOTE: Cannot be called from within a background task. Use close_from_task() for that.
        """
        for task in self.background_tasks:
            self.remove_task(task)
        if self.websocket != None:
            await self.websocket.close()
            self.websocket = None

    async def close_from_task(self, current_task: str):
        """
        Same as close, but can be called by a background task without cancelling itself.
        """
        for task in self.background_tasks:
            if task == current_task:
                continue
            self.remove_task(task)
        if self.websocket != None:
            await self.websocket.close()
            self.websocket = None

    async def send(self, channel: str, message: str):
        """
        Send a PRIVMSG to the specified channel, causing the bot
        to speak in the chat.
        """
        await self.irc_send(f"PRIVMSG {validate_channel(channel)} :{message}")

    async def reply(self, original_message: ChatMessage, reply: str):
        """
        Sends a reply in the chat to a previously sent message.
        """
        await self.irc_send(f"@reply-parent-msg-id={original_message.id} PRIVMSG {validate_channel(original_message.channel)} :{reply}")

    async def irc_send(self, message: str):
        """
        Send a raw message to the underlying websocket.

        Note: Not for sending messages in the chat.
        """
        await self.websocket.send(message)

    def parse_tags(self, raw_tags: str) -> Dict[str, str]:
        tags = {}
        for tag_pair in raw_tags.split(';'):
            key, value = tag_pair.split('=', 1)
            tags[key] = value
        return tags

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

    async def validate_token_worker(self):
        while True:
            await asyncio.sleep(3600)
            try:
                await self.validate_token()
            except:
                print("[!] Error: token validation failed, attempting to reconnect")
                self.add_task('reconnect', self.reconnect_worker())

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
                    await callback_task
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
            print(f"[!] Connect attempt failed. Trying again in {wait_interval} second(s)")
            # Cleanup old tasks
            self.remove_task('ping')
            self.remove_task('dispatch')
            self.remove_task('validate_token')
            # Cleanup old websocket
            if self.websocket is not None:
                await self.websocket.close()
                self.websocket = None
            # Wait for back-off interval
            await asyncio.sleep(wait_interval)
            # Try to connect
            try:
                await self.connect()
                await self.join(*self.channels)
                break
            # On 401, refresh the token and continue
            except AuthError:
                print("[!] Token invalid or expired, attempting to refresh")
                try:
                    await self.token.refresh(self.client_id, self.client_secret)
                    await self.on_token_refresh(self.token)
                    continue
                # If the refresh fails, just quit the app
                except:
                    await self.close_from_task('reconnect')
                    return
            # On anything other than 401, back off and try again
            except:
                wait_interval *= 2

    ###################
    # Event Callbacks #
    ###################

    async def on_token_refresh(self, token: Token):
        """
        Fires whenever a 401 is received and the token is successfully refreshed.
        """
        pass

    async def on_irc_message(self, message: IRCMessage):
        """
        Fires on all IRC messages, not just chat messages. Some examples
        are JOIN, PRIVMSG, and USERSTATE.

        Responsible for triggering all other event callbacks - if you overload
        this function, you're taking on the responsibility of either calling this
        function by super().on_irc_message() or handling task timeouts such as
        successful auth responses and join responses.
        """
        if self.log_irc:
            print("[!] IRC Message", message)

        if message.command == '001':
            self.resolve_future('auth')

        elif message.command == 'JOIN':
            self.resolve_future('join', message.parameters)

        elif message.command == 'PING':
            await self.irc_send(f"PONG :{message.body}")

        elif message.command == 'ROOMSTATE':
            await self.on_room_state(message.parameters[0] if message.parameters else None, message.tags)

        elif message.command == 'USERNOTICE':
            await self.on_user_notice(message.parameters[0] if message.parameters else None, message.body, message.tags)

        elif message.command == 'CLEARMSG':
            await self.on_message_deleted(message.tags.get("target-msg-id"))

        elif message.command == 'PRIVMSG':
            await self.on_chat_message(ChatMessage(
                message.tags.get('id'),
                message.body,
                message.parameters[0] if message.parameters else None,
                message.tags.get('user-id', None),
                message.tags.get('display-name', None),
                'broadcaster' in message.tags.get('badges', ''),
                message.tags.get('mod', None) == '1',
                message.tags.get('vip', None) is not None,
                message.tags.get('subscriber', None) == '1',
                'staff' in message.tags.get('badges', ''),
                message.tags.get('first-msg', None) == '1',
                False,
                message.tags.get('color', None),
                int(datetime.now().timestamp()),
            ))

        elif message.command == 'WHISPER':
            await self.on_whisper(ChatMessage(
                message.tags.get('message-id'),
                message.body,
                channel=None,
                user_id=None,
                user_name=message.parameters[0] if message.parameters else None,
                is_broadcaster=None,
                is_mod=None,
                is_vip=None,
                is_subscriber=None,
                is_staff=None,
                is_first_message=None,
                is_whisper=True,
                color=None,
                timestamp=int(datetime.now().timestamp()),
            ))

    async def on_room_state(self, channel: str, tags: Dict[str,str]):
        """
        Fires when the bot joins a channel or when the channel’s chat settings change.
        """
        pass

    async def on_user_notice(self, channel: str, text: str, tags: Dict[str,str]):
        """
        Fires when these events occur:

        - A user subscribes to the channel, re-subscribes to the channel, or gifts a
        subscription to another user.

        - Another broadcaster raids the channel.

        - A viewer milestone is celebrated such as a new viewer chatting for the
        first time.
        """
        pass

    async def on_message_deleted(self, message_id: str):
        """
        Fires when a message is deleted by a moderator.
        """
        pass

    async def on_chat_message(self, message: ChatMessage):
        """
        Fires when a message is received in a channel that the bot is
        subscribed to by calling join() after create()

        If overloaded in a subclass, super().on_chat_message() should
        be called to dispatch and chat commands.
        """
        if self.log_chat:
            if message.is_broadcaster:
                print(f"[{message.channel}] (BROADCASTER) {message.user_name}: \"{message.text}\"")
            elif message.is_mod:
                print(f"[{message.channel}] (MOD) {message.user_name}: \"{message.text}\"")
            elif message.is_vip:
                print(f"[{message.channel}] (VIP) {message.user_name}: \"{message.text}\"")
            elif message.is_subscriber:
                print(f"[{message.channel}] (SUB) {message.user_name}: \"{message.text}\"")
            else:
                print(f"[{message.channel}] {message.user_name}: \"{message.text}\"")

        # Check if any commands need to be called
        if not message.text.startswith(self.command_prefix):
            return

        try:
            command_name, *message_args = shlex.split(message.text)
        except ValueError:
            command_name, *message_args = message.text.split()

        command = self.registered_commands.get(command_name[len(self.command_prefix):].lower())
        if command is None:
            return

        if message.permission < command.permission:
            return

        callback_args = []
        args_consumed = 0
        for parameter in command.parameters:
            # ChatMessage parameters are given the current message and skipped
            if parameter.annotation is ChatMessage:
                callback_args.append(message)
                continue
            # Get the next arg from message_args, or None
            try:
                arg = message_args[args_consumed]
                args_consumed += 1
            except IndexError:
                arg = None
            # If arg is not present, use default value (or error if no default)
            if arg is None:
                if parameter.default is inspect.Parameter.empty:
                    raise ValueError(f"missing argument to parameter '{parameter.name}' on command '{command_name}'")
                callback_args.append(parameter.default)
            # If arg is present, pass through type constructor
            else:
                if parameter.annotation is inspect.Parameter.empty:
                    callback_args.append(arg)
                else:
                    callback_args.append(parameter.annotation(arg))

        # Make sure no more arguments were passed than parameters on the callback
        if args_consumed != len(message_args):
            raise ValueError(f"command '{command_name}' received unused arguments: {message_args[args_consumed:]}")

        await command.callback(*callback_args)

    async def on_whisper(self, message: ChatMessage):
        """
        Fires when a whisper is received. The whisper does not contain very
        much information, the @tags mostly contain information about the
        whisper recipient (the bot user).

        The useful pieces of information are message.user_name and message.text

        Note: You cannot reply to a whisper with self.reply()
        """
        print(f"[Whisper] {message.user_name}: \"{message.text}\"")
