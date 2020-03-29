#!/usr/bin/env python3
import asyncio
import concurrent.futures
import os.path
import pickle
import random
import string
import sys
import timeit
from asyncio import open_connection, get_event_loop, StreamReader, StreamWriter
from base64 import b64encode, b64decode
from traceback import TracebackException
from typing import Optional, NoReturn, Dict, Tuple, Set
from OpenSSL import crypto #type: ignore


OK, CORRUPT, MUMBLE, DOWN, CHECKER_ERROR = 101, 102, 103, 104, 110
PORT = 9876
ServiceName = "strange"

def randbits(size: int) -> int:
    r = random.getrandbits(size)
    r |= 1 << (size - 1)
    return r


def verdict(exit_code: int, public: str = "", private: str = "") -> NoReturn:
    if len(public) > 0:
        print(public)
    if len(private) > 0:
        print(private, file=sys.stderr)
    sys.exit(exit_code)

def verdict_ok() -> NoReturn:
    verdict(OK)
def corrupt(details: str) -> NoReturn:
    verdict(CORRUPT, "Corrupt", details)
def mumble(details: str) -> NoReturn:
    verdict(MUMBLE, "Mumble", details)
def down(details: str) -> NoReturn:
    verdict(DOWN, "Down", details)


def rand_string(length: int = 16) -> str:
    letters = string.ascii_letters + string.digits
    name = "".join(random.choice(letters) for _ in range(length))
    return name
def rand_bytes(length: int = 16) -> bytes:
    return rand_string(length).encode()

class Storage:
    class User:
        name: bytes
        private_key: bytes
        certificate: bytes
        tainted: bool

        def __init__(self, name = b"", key = b"", cert = b""):
            self.name = name
            self.private_key = key
            self.certificate = cert
            self.tainted = False

        @staticmethod
        def generate(name: bytes) -> 'Storage.User':
            key_obj = crypto.PKey()
            key_obj.generate_key(crypto.TYPE_RSA, 512)
            private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_obj).decode()
            #
            cert_obj = crypto.X509()
            subject = cert_obj.get_subject()
            subject.CN = "ru"
            subject.C = "RU"
            subject.ST = "Tomskaya obl"
            subject.L = "Seversk"
            subject.O = "ooo"
            subject.OU = "ouu"
            cert_obj.set_serial_number(1000)
            cert_obj.gmtime_adj_notBefore(0)
            cert_obj.gmtime_adj_notAfter(315360000)
            cert_obj.set_issuer(subject)
            cert_obj.set_pubkey(key_obj)
            cert_obj.sign(key_obj, "sha256")
            cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert_obj).decode()

            user = Storage.User(name)
            user.private_key = private_key.encode()
            user.certificate = cert.encode()
            return user

        def dump(self) -> bytes:
            vals = [self.name, b64encode(self.private_key), b64encode(self.certificate)]
            return b"#".join(vals)

        @staticmethod
        def load(line: bytes) -> 'Storage.User':
            name, enc_key, enc_cert = line.split(b"#")
            user = Storage.User(name, b64decode(enc_key), b64decode(enc_cert))
            return user

    # flag to user
    users: Dict[str, User]
    yolo_mode: bool
    store_path: str
    shared_path: str
    def __init__(self, path: str, shared_path: str) -> None:
        self.store_path = path
        self.shared_path = shared_path
        # default values
        self.users = {}
        self.yolo_mode = False
    def dump(self) -> None:
        if self.yolo_mode:
            return
        with open(self.store_path, "wb") as f:
            pickle.dump(self, f)
    @staticmethod
    def load(path: str, shared_path: str) -> 'Storage':
        if os.path.isfile(path):
            with open(path, "rb") as f:
                store = pickle.load(f)
                store.store_path = path
                store.shared_path = shared_path
                return store
        else:
            default = Storage(path, shared_path)
            default.dump()
            return default

    def new_user(self) -> User:
        if self.yolo_mode:
            name = rand_bytes()
            user = Storage.User.generate(name)
            return user
        lines = []

        if os.path.isfile(self.shared_path):
            with open(self.shared_path, "rb") as f:
                lines = f.read().strip().split(b"\n")
            stored_users = map(Storage.User.load, lines)
            have_users = set(user.name for user in self.users.values())
            for user in stored_users:
                if user.name not in have_users:
                    return user
        # either file doesn't exist, or no unused user
        name = rand_bytes()
        user = Storage.User.generate(name)
        with open(self.shared_path, "ab") as f:
            f.write(user.dump() + b"\n")
        return user

async def timed(aw, timeout=5.0):
    return await asyncio.wait_for(aw, timeout=timeout)


async def check(store: Storage, host: str) -> NoReturn:
    if len(store.users) == 0:
        verdict_ok()
    flag = random.choice(list(store.users.keys()))
    await get_flag(store, host, "", flag, "")
    verdict_ok()

async def put_flag(store: Storage, host: str, flag_id, flag: str, vuln) -> NoReturn:
    was_connected = False
    reader, writer = await timed(open_connection(host, PORT))
    while not was_connected:
        greet = await reader.readline()
        if greet != b"name\n":
            mumble(f"Bad greeting: {greet}")

        user = store.new_user()
        writer.write(user.name + b"\n")
        resp = await timed(reader.readline())
        if resp == b"exchange\n":
            # retry
            user.tainted = True
            store.users[flag + rand_string()] = user
            store.dump()
            reader, writer = await timed(open_connection(host, PORT))
            continue
        elif resp == b"certificate\n":
            was_connected = True
            break
        else:
            mumble(f"Bad auth request: {resp}")
    writer.write(user.certificate)
    resp = await timed(reader.readline())
    if resp != b"ok\n":
        mumble(f"Bad auth response: {resp}")

    writer.write(b"put\n")
    writer.write(flag.encode() + b"\n")
    resp = await timed(reader.readline())
    if resp != b"ok\n":
        mumble(f"Bad put response: {resp}")

    store.users[flag] = user
    store.dump()

    verdict_ok()


async def get_flag(store: Storage, host: str, flag_id, flag: str, vuln) -> NoReturn:
    if flag not in store.users:
        verdict(CHECKER_ERROR, "Bad flag", "Flag was never stored")
    user = store.users[flag]
    reader, writer = await timed(open_connection(host, PORT))
    greet = await reader.readline()
    if greet != b"name\n":
        mumble(f"Bad greeting: {greet}")
    writer.write(user.name + b"\n")
    resp = await timed(reader.readline())
    if resp != b"exchange\n":
        mumble(f"Bad auth request: {resp}")

    bitsize = 256
    str_len = bitsize // 4 + 2
    client_eph: int
    server_eph: int

    client_eph = randbits(bitsize)
    client_eph_str = hex(client_eph).encode()
    writer.write(client_eph_str + b"\n")
    resp = await timed(reader.readline())
    if resp.startswith(b"too short"):
        mumble(f"too short: {client_eph_str} - {resp}")
    elif resp.startswith(b"not a number"):
        mumble(f"not a number: {client_eph_str} - {resp}")
    if resp == b"too short\n" or resp == b"not a number\n":
        mumble("Server dal yobu")
    try:
        server_eph = int(resp.strip(), 16)
    except ValueError:
        mumble(f"Not a number: {resp}")
    data = hex(server_eph * client_eph).encode()
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, user.private_key)
    signature = crypto.sign(key, data, "sha256")
    writer.write(b64encode(signature) + b"\n")
    resp = await timed(reader.readline())
    if resp != b"ok\n":
        mumble("Failed to verify")

    writer.write(b"get\n")
    store_flag = await timed(reader.readline())
    if store_flag.strip().decode() != flag:
        corrupt(f"Bad flag: {store_flag} vs {flag} for user {user.name}")

    verdict_ok()

async def stress_test(store: Storage, host: str) -> NoReturn:
    real_exit = sys.exit
    def fake_exit(code: int) -> None:
        if code == OK:
            pass
        else:
            real_exit(code)
    sys.exit = fake_exit #type: ignore
    store.yolo_mode = True

    task_amount = random.randrange(100, 200)
    print(f"spawning {task_amount} workers")

    async def wrapped_get() -> None:
        flag = ""
        while flag == "":
            flag = random.choice(list(store.users.keys()))
            if store.users[flag].tainted:
                flag = ""
        await get_flag(store, host, "", flag, None)
    async def wrapped_put() -> None:
        flag = rand_string(32)
        await put_flag(store, host, "", flag, None)

    tasks = [random.choice([wrapped_get, wrapped_put])() for _ in range(task_amount)]
    start = timeit.default_timer()
    await asyncio.gather(*tasks)
    end = timeit.default_timer()
    sys.exit = real_exit
    print(f"all workers finished in {end - start} seconds")
    verdict_ok()


if __name__ == "__main__":
    try:
        command = sys.argv[1]
        host = sys.argv[2]

        dbname = f"storage-{ServiceName}-{host}-{PORT}.dump"
        shared_db_name = f"storage-{ServiceName}-shared.dump"
        store = Storage.load(dbname, shared_db_name)
        loop = get_event_loop()

        if command == "check":
            loop.run_until_complete(check(store, host))

        elif command == "put":
            flag_id, flag_data, vuln = sys.argv[3:]
            loop.run_until_complete(put_flag(store, host, flag_id, flag_data, vuln))

        elif command == "get":
            flag_id, flag_data, vuln = sys.argv[3:]
            loop.run_until_complete(get_flag(store, host, flag_id, flag_data, vuln))

        elif command == "stresstest":
            loop.run_until_complete(stress_test(store, host))
            verdict_ok()

        else:
            verdict(CHECKER_ERROR, "Wrong action", "Wrong action: " + command)

    except IndexError as e:
        trace = "".join(TracebackException.from_exception(e).format())
        verdict(CHECKER_ERROR, "Not enough arguments", trace)
    except ValueError as e:
        trace = "".join(TracebackException.from_exception(e).format())
        verdict(CHECKER_ERROR, "Not enough arguments", trace)
    except ConnectionRefusedError as e:
        trace = "".join(TracebackException.from_exception(e).format())
        down(trace)
    except AssertionError as e:
        trace = "".join(TracebackException.from_exception(e).format())
        verdict(CHECKER_ERROR, "Bad parameters", trace)
    except concurrent.futures._base.TimeoutError as e:
        trace = "".join(TracebackException.from_exception(e).format())
        mumble(trace)
    except Exception as e:
        trace = "".join(TracebackException.from_exception(e).format())
        verdict(CHECKER_ERROR, "Other error", trace)

    verdict(CHECKER_ERROR, "Checker error (CE)", "No verdict")
