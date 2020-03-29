#!/usr/bin/env python3
import aiomysql #type: ignore
import random
from asyncio import get_event_loop, start_server, StreamReader, StreamWriter
from base64 import b64decode
from OpenSSL import crypto #type: ignore

DbCreds = { "host": "127.0.0.1"
          , "user": "stranger"
          , "password": "a1b463c34866e45e5e7d959970228eac"
          , "db": "armsrace"
          }

mysql_pool = None

def randbits(size: int) -> int:
    r = random.getrandbits(size)
    r |= 1 << (size - 1)
    return r


async def login(reader: StreamReader, writer: StreamWriter, cur, name: str) -> bool:
    bitsize = 256
    str_len = bitsize // 4 + 2
    client_eph: int
    server_eph: int

    writer.write(b"exchange\n")
    client_eph_str = await reader.readline()
    client_eph_str = client_eph_str.strip()
    if len(client_eph_str) != str_len:
        writer.write(b"too short\n")
        return False
    try:
        client_eph = int(client_eph_str, 16)
    except ValueError:
        writer.write(b"not a number\n")
        return False

    server_eph = randbits(bitsize)
    server_eph_str = hex(server_eph).encode()
    writer.write(server_eph_str + b"\n")

    data = hex(server_eph * client_eph).encode()
    signature = b64decode(await reader.readline())
    await cur.execute("select certificate from users where name = %s", (name,))
    (public_key,) = await cur.fetchone()

    try:
        key = crypto.load_certificate(crypto.FILETYPE_PEM, public_key.encode())
        crypto.verify(key, signature, data, "sha256")
    except crypto.Error as e:
        print(f"Verification failed: {e}")
        writer.write(b"fail\n")
        writer.write_eof()
        return False

    writer.write(b"ok\n")
    return True

async def register(reader, writer, cur, name: str) -> bool:
    writer.write(b"certificate\n")
    certificate = await reader.readuntil(b"-----END CERTIFICATE-----\n")
    certificate = certificate.decode()
    await cur.execute("insert into users (name, certificate) value (%s, %s)"
                     , (name, certificate))
    writer.write(b"ok\n")
    return True

async def handler(reader, writer) -> None:
    print("Got a new connection")

    global mysql_pool
    if mysql_pool is None:
        writer.write(b"database error\n")
        return

    async with mysql_pool.acquire() as conn:
        async with conn.cursor() as cur:
            writer.write(b"name\n")
            name = await reader.readline()
            name = name.strip()
            await cur.execute("select count(*) from users where name = %s"
                             , (name,))
            (count,) = await cur.fetchone()

            success = True
            if count == 0:
                success = await register(reader, writer, cur, name)
                await conn.commit()
            else:
                success = await login(reader, writer, cur, name)
            if not success:
                return

            command = await reader.readline()
            command = command.strip()

            if command == b"put":
                data = await reader.readline()
                data = data.strip()
                await cur.execute("update users set note = %s where name = %s"
                           , (data, name))
                await conn.commit()
                writer.write(b"ok\n")

            elif command == b"get":
                await cur.execute("select note from users where name = %s", (name,))
                (data,) = await cur.fetchone()
                writer.write(data.encode() + b"\n")


if __name__ == "__main__":
    loop = get_event_loop()
    async def server() -> None:
        global mysql_pool
        print("Connecting to database")
        mysql_pool = await aiomysql.create_pool(**DbCreds)
        async with mysql_pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute( "create table if not exists users"
                                 + "( rowid integer primary key auto_increment"
                                 + ", name text not null"
                                 + ", certificate text not null"
                                 + ", note text"
                                 + ")"
                                 )
        #
        print("Starting server")
        s = await start_server(handler, "0.0.0.0", 9876)
        await s.wait_closed()
    loop.run_until_complete(server())
