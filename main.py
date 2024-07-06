# 1.1.2
import asyncio
import binascii
from contextlib import asynccontextmanager
import time
import pywebio  # type: ignore
import pywebio.output as output  # type: ignore
import pywebio.input as input  # type: ignore
import aiosqlite
import functions

from pywebio.session import run_async, set_env  # type: ignore

# MAX_MESSAGES_CNT = 200


class AsyncDatabaseConnectionManager:
    _instance = None
    _lock = asyncio.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AsyncDatabaseConnectionManager, cls).__new__(cls)
            cls._instance.connections = {}
        return cls._instance

    async def get_connection(self, db_name):
        if db_name not in self.connections:
            self.connections[db_name] = await aiosqlite.connect(db_name)
        return self.connections[db_name]

    @asynccontextmanager
    async def connection_context(self, db_name):
        connection = await self.get_connection(db_name)
        try:
            yield connection
        finally:
            pass

    async def close_all_connections(self):
        for connection in self.connections.values():
            await connection.close()
        self.connections.clear()


db_manager = AsyncDatabaseConnectionManager()


async def _input(label: str, *args, **kwargs):
    name = {"name": "data"}
    if "name" in kwargs:
        name = {}
    _input = await input.input_group(
            label,
            inputs=[
                input.input(
                    *args, **kwargs, **name
                ),
                pywebio.input.actions(
                    name="action",
                    buttons=[
                        {"label": "Submit", "value": "submit", "color": "primary"},
                        {"label": "Reset", "type": "reset", "color": "warning"}
                    ]
                )
            ])
    return _input


@pywebio.config(theme='dark')
async def main():
    set_env(title='Login', output_animation=False)
    output.toast("Created by mrdan__")

    async def join_room():
        output.close_popup()
        success = False
        while not success:
            passphrase = (await _input("Room key", type=input.PASSWORD, required=True))["data"]
            room = await functions.load_room(passphrase)
            success = room.load_success
            if not success:
                output.toast("No room found with this key", duration=3, color="error")
        success = False
        username = ""
        user_exists = False
        while not success:
            _username = (await _input("Username", required=True))["data"]
            user = functions.User(_username)
            async with aiosqlite.connect(functions.room_db(room.id)) as db:
                user_exists = await user.exists(db)
            if not user_exists:
                agree = (await _input(f"\"{_username}\" is you username? (yes/no)", required=True))["data"]
                if str(agree).lower() in ["yes", "yh", "ofc", "yeah"]:
                    username = _username
                    success = True
            else:
                username = _username
                success = True

        if not user_exists:
            output.toast("This account does not exist, a new one will be created")
            success = False
            password = ""
            while not success:
                result = await input.input_group(
                    label="New password",
                    inputs=[
                        input.input(type=input.PASSWORD, name="password1", placeholder="Password"),
                        input.input(type=input.PASSWORD, name="password2", placeholder="Repeat password"),
                        pywebio.input.actions(
                            name="action",
                            buttons=[
                                {"label": "Submit", "value": "submit", "color": "primary"},
                                {"label": "Reset", "type": "reset", "color": "warning"}
                            ]
                        )
                    ]
                )
                if result["password1"] == result["password2"]:
                    success = True
                    password = result["password1"]
                else:
                    output.toast("Password mismatch", color="error")
            async with aiosqlite.connect(functions.room_db(room.id)) as db:
                user = await functions.create_user(username, password, db)
                await db.commit()
        else:
            success = False
            while not success:
                password = (await _input("Password", required=True, type=input.PASSWORD))["data"]
                user.password_sha256 = functions.sha256(password)
                async with aiosqlite.connect(functions.room_db(room.id)) as db:
                    if await user.check_password(db):
                        success = True
                    else:
                        output.toast("Wrong password", color='error')
        run_async(chat(user, room))

    async def create_room():
        new_room = await functions.create_room()
        output.close_popup()
        output.popup(
            title='Succes!',
            content=[
                output.put_markdown("# If you lose this key you will never be able to enter the room again."),
                output.put_markdown(f"### Key: \n{new_room.passphrase}"),
                output.put_button("Join room", onclick=join_room)
            ],
            closable=False
        )

    output.popup(
        title='Hi! What do you want to do?',
        content=[
            output.put_button("Join room", onclick=join_room),
            output.put_button("Create room", onclick=create_room,)
        ],
        closable=False
    )


class RefreshMsg:
    def __init__(self, msg_box: output.OutputList, room: functions.Room) -> None:
        self.msg_box = msg_box
        self.last_index = 0
        self.room = room
        self.messages: list = []

    async def refresh_msg(self, db: aiosqlite.Connection):
        sql = await db.cursor()
        await asyncio.sleep(1)
        while True:
            await asyncio.sleep(0.5)
            messages = await (await sql.execute(
                "SELECT id, nickname, message, created_at, type FROM messages ORDER BY id DESC LIMIT 25"
            )).fetchall()
            messages = list(messages)
            messages.reverse()
            if messages:
                if self.last_index < messages[len(messages)-1][0]:
                    self.messages = messages
                    for x in messages:
                        if x[0] <= self.last_index:
                            continue
                        try:
                            private_key = self.room.private_key
                            passphrase = self.room.passphrase
                            if isinstance(private_key, (bytes, str)) and isinstance(passphrase, str):
                                msg = functions.decrypt_message(x[2], private_key, passphrase)
                            else:
                                raise TypeError("'room.public_key' or 'room.passphrase' type must be 'bytes'")
                        except binascii.Error:
                            msg = x[2]
                        except ValueError:
                            msg = x[2]
                        nickname = x[1] if x[4] != 2 else '📢'
                        self.msg_box.append(output.put_markdown('`%s`: %s' % (nickname, msg), sanitize=True))
                    if self.last_index == 0:
                        ...
                    self.last_index = messages[len(messages)-1][0]


async def add_msg(
            msg: str, user: functions.User,
            room: functions.Room, db: aiosqlite.Connection, type: int = 1
        ):
    sql = await db.cursor()
    if isinstance(room.public_key, (bytes, str)) and isinstance(room.passphrase, str):
        encrypted_msg = functions.encrypt_message(msg, room.public_key, room.passphrase)
    else:
        raise TypeError("'room.public_key' or 'room.passphrase' type must be 'bytes'")
    await sql.execute(
        "INSERT INTO messages (nickname, message, type) VALUES (?, ?, ?)",
        (user.nickname, encrypted_msg, type)
    )
    await db.commit()


async def online(user: functions.User, db: aiosqlite.Connection, msg_box: output.OutputList):
    sql = await db.cursor()
    _offline_list = None
    _online_list = None
    while True:
        await asyncio.sleep(1)
        await sql.execute("SELECT nickname, online_timestamp FROM online")
        online_list = await sql.fetchall()
        if _offline_list is None and _online_list is None:
            _offline_list = []
            _online_list = []
            for nickname, online_timestamp in online_list:
                if time.time()-15 > online_timestamp:
                    _offline_list.append(nickname)
                else:
                    _online_list.append(nickname)
        user_in_list = False
        for nickname, online_timestamp in online_list:
            if nickname == user.nickname:
                user_in_list = True
            if time.time()-15 > online_timestamp and nickname not in _offline_list:
                msg_box.append(output.put_markdown('`%s`: %s' % ('📢', f'`{nickname}` leaves the room.'), sanitize=True))
                _offline_list.append(nickname)
                if nickname in _online_list:
                    _online_list.remove(nickname)
            elif time.time()-15 < online_timestamp and nickname not in _online_list:
                msg_box.append(output.put_markdown('`%s`: %s' % ('📢', f'`{nickname}` joins the room.'), sanitize=True))
                _online_list.append(nickname)
                if nickname in _offline_list:
                    _offline_list.remove(nickname)

        if user_in_list:
            await sql.execute(
                "UPDATE online SET online_timestamp = ? WHERE nickname = ?",
                (time.time(), user.nickname)
            )
        else:
            await sql.execute(
                "INSERT INTO online (nickname, online_timestamp) VALUES (?, ?)",
                (user.nickname, time.time())
            )
        await db.commit()


async def chat(user: functions.User, room: functions.Room):
    set_env(title='Chat', output_animation=False)
    if room.id is not None:
        room_db = functions.room_db(room.id)
    else:
        raise TypeError("'room.id' type must be 'str'")
    msg_box = output.output()
    output.put_scrollable(msg_box, height=300, keep_bottom=True)
    async with db_manager.connection_context(room_db) as db:
        refresher = RefreshMsg(msg_box, room)
        run_async(refresher.refresh_msg(db))
        run_async(online(user, db, msg_box))

        while True:
            data = await input.input_group('Send message', [
                input.input(name='msg', help_text='Message content supports inline Markdown syntax'),
                input.actions(name='cmd', buttons=['Send', 'Multiline Input', {'label': 'Exit', 'type': 'cancel'}])
            ], validate=lambda d: ('msg', 'Message content cannot be empty') if d['cmd'] == 'Send' and not d['msg'] else None)
            if data is None:
                break
            if data['cmd'] == 'Multiline Input':
                data['msg'] = '\n' + await input.textarea('Message content', help_text='Message content supports Markdown syntax')
            await add_msg(data['msg'], user, room, db)

    output.toast("You have left the chat room")


if __name__ == '__main__':
    pywebio.start_server(main, debug=False, port=8080, reconnect_timeout=15)
