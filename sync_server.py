from aiohttp import web
import aiohttp
import socket
import os
import bot_api
from aiohttp import web_request
import json
import asyncio.subprocess as suprocess
import asyncio
from google.cloud import pubsub_v1


async def test_check(request: aiohttp.web_request.Request):
    return web.Response(text="")


async def han_complete(request: aiohttp.web_request.Request):
    text: str = await request.text()
    complete: bot_api.BatchCompleted = bot_api.BatchCompleted.from_json(text)
    sync_script_location = "/usr/local/bin/send_to_server.sh"
    try:
        sync: suprocess.Process = await suprocess.create_subprocess_exec("sh", sync_script_location,
                                                                     stderr=asyncio.subprocess.PIPE,
                                                                     stdout=asyncio.subprocess.PIPE)
        stdout, stderr = await sync.communicate()
        returncode: int = sync.returncode
        if returncode != 0:
            err_msg: bot_api.BatchSyncErrMsg = bot_api.BatchSyncErrMsg(returncode=returncode,
                                                                       stdout=stdout.decode(),
                                                                       stderr=stderr.decode())
            data = bot_api.BatchSyncError(err_info=err_msg)
        else:
            data = bot_api.BatchSyncComplete()
        msg = bot_api.BatchSynced(batch_info=complete,
                            sync_result=data)
        print(msg.to_json())
        publisher.publish(topic, msg.to_json().encode())
        return web.Response(text=msg.to_json())
    except FileNotFoundError:
        err_msg = bot_api.BatchSyncErrMsg(returncode=1,
                                          stdout="",
                                          stderr=f"{sync_script_location}, does not exist")
        data = bot_api.BatchSyncError(err_msg)
        msg = bot_api.BatchSynced(batch_info=complete,
                                  sync_result=data)
        return web.Response(text=json.dumps(msg.to_json()))
    except OSError as e:
        err_msg = bot_api.BatchSyncErrMsg(returncode=1,
                                          stdout="",
                                          stderr=str(e))
        data = bot_api.BatchSyncError(err_msg)
        msg = bot_api.BatchSynced(batch_info=complete,
                                  sync_result=data)

        return web.Response(text=json.dumps(msg.to_json()))

if __name__ == "__main__":

    try:
        project_id: str = os.environ["GOOGLE_CLOUD_PROJECT"]
    except KeyError:
        raise ValueError("GOOGLE_CLOUD_PROJECT not set in env")

    try:
        credential_location: str = os.environ["GOOGLE_APPLICATION_CREDENTIALS"]
    except KeyError:
        raise ValueError("GOOGLE_APPLICATION_CREDENTIALS were not set")
    server_address = '/home/bot_sync/socks/sync.sock'
    print(server_address)
    publisher: pubsub_v1.PublisherClient = pubsub_v1.PublisherClient()
    topic: str = publisher.topic_path(project_id, topic="batch")
    print(type(topic))
    print(topic)
    # Make sure the socket does not already exist
    try:
        os.unlink(server_address)
    except OSError:
        if os.path.exists(server_address):
            raise

    # Create a UDS socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(server_address)

    app = web.Application()
    app.add_routes([web.post("/", han_complete),
                    web.get("/test", test_check),
                    ])
    web.run_app(app, sock=sock)
