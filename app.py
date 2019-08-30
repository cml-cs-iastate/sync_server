import io
import re
from typing import List
from aiohttp import web
import aiohttp
import socket
import bot_api
from aiohttp import web_request
import json
import asyncio.subprocess as suprocess
import asyncio
from google.cloud import pubsub_v1
from pathlib import Path
import os
from typing import Optional

from glob import iglob
from bs4 import BeautifulSoup
from typing import Iterator
import pathlib
from pathlib import Path
import more_itertools
from more_itertools import first, ilen
from bot_api import (BatchSyncComplete, BatchSyncStatus, BatchSynced, BotEvents, BatchCompleted, BatchCompletionStatus)
from datetime import datetime


from typing import Union
from django.core.exceptions import ObjectDoesNotExist

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sync_server.settings")

from dataclasses import dataclass

class AdFile:
    def __init__(self, filename: pathlib.Path):
        (self.bot_name,
        self.try_num,
        self.ad_seen_at,
        self.video_watched) = filename.stem.split("#")

class AdStorage:
    def __init__(self, ad_dir: pathlib.Path):
        self.path = ad_dir
        self.run_id = int(self.path.name)
        (self.host_hostname, self.hostname) = self.path.parents[0].name.split("#")
        self.location = self.path.parents[1].name

@dataclass()
class SyncContext:
    # directory where ads are stored in
    ad_base_dir: Path
    # Directory of specific batch of ads
    #ad_specific_dir: Path
    # hostname/ip to move ads to
    storage_hostname: str
    # username to login to the server in
    storage_user: str
    # base directory to copy ads into
    storage_base_dir: Path
    # pubsub client
    publisher: pubsub_v1
    # pubsub topic
    publisher_topic: str


def count_txt_files(ad_dir: pathlib.Path) -> int:
    """Ad format v3"""
    return ilen(ad_dir.glob("*.txt"))


def count_xml_files(ad_dir: pathlib.Path) -> int:
    return ilen(xml_files(ad_dir))


def xml_files(ad_dir: pathlib.Path) -> Iterator[pathlib.Path]:
    return ad_dir.glob("*.xml")


def html_files(ad_dir: pathlib.Path) -> Iterator[pathlib.Path]:
    return ad_dir.glob("*.html")


def extract_ip_from_html_player(html_filehandle: io.TextIOWrapper):
    """Returns 0.0.0.0 if no ip address is found in the html file"""
    html_file = html_filehandle.read()
    ip_containing = re.search(r"(?:\\u0026v|%26|%3F)ip(?:%3D|=)(.*?)(?:,|;|%26|\\u0026)", html_file, re.DOTALL)
    if ip_containing is None:
        return "0.0.0.0"
    return ip_containing.group(1)


def count_non_ad_requests(ad_dir: pathlib.Path) -> int:
    try:
        return ilen(ad_dir.joinpath("noAds.csv").open())
    except FileNotFoundError:
        return 0


def last_request_time(ad_dir: pathlib.Path) -> int:
    """Returns -1 for a request time if there were no requests with no ads"""
    try:
        ad_filenames = ad_dir.joinpath("noAds.csv").open().read().splitlines()[-10:]
        for ad_filename in reversed(ad_filenames):
            try:
                abs_ad_filepath: pathlib.Path = ad_dir / ad_filename
                return int(AdFile(abs_ad_filepath).ad_seen_at)
            except (AttributeError, ValueError) as e:
                # Possible file corruption
                print("FILE CORRUPTION IN FOLLOWING DIRECTORY")
                print(abs_ad_filepath)
                continue
        else:
            return -1
    except FileNotFoundError:
        version = deterimine_ad_format_version(ad_dir)
        if version == 3:
            ads = list(ad_dir.glob("*.txt"))
        elif version == 2:
            ads = list(ad_dir.glob("*.json"))
        elif version == 1:
            ads = list(ad_dir.glob("*.xml"))
        else:
            raise NotImplemented(f"ad format `{version}` not implemented for finding last timestamp")

        if len(ads) == 0:
            return -1

        latest = -1
        for file in ads:
            if "run_type.txt" in file.as_posix():
                continue
            try:
                ad = AdFile(file)
            except Exception as e:
                print("DDDD", e, file)
                raise e
            if ad.ad_seen_at > latest:
                latest = ad.ad_seen_at
        return latest


def messages_from_file(file: pathlib.Path) -> List[BatchSynced]:
    with file.open() as f:
        messages = f.readlines()
    return [BatchSynced.from_json(message) for message in messages]


def batch_is_old(completion_msg: BatchCompleted):
    age_of_batch = datetime.now() - datetime.utcfromtimestamp(completion_msg.timestamp)
    age_days_threshold = 2
    return age_of_batch.days >= age_days_threshold


async def test_check(request: aiohttp.web_request.Request):
    return web.Response(text="")


async def test_post(request: aiohttp.web_request.Request):
    content = await request.json()
    return web.json_response(data=content)


async def sync_directory(src: Path, sync_context: SyncContext) -> Union[BatchSyncComplete, bot_api.BatchSyncError]:
    rsync_commands = ["rsync", "-a", "--relative",
                      # example: /home/alex/github/dumps/./louisiana/node12.misc.iastate.edu#e6ede031d296/1564364031
                                  ####src_base##########   ######################src################################
                      f"{sync_context.ad_base_dir.as_posix()}/./{src.relative_to(sync_context.ad_base_dir).as_posix()}",
                      f"{sync_context.storage_user}@{sync_context.storage_hostname}:{sync_context.storage_base_dir.as_posix()}"]
    print("rsync commands:", rsync_commands)
    sync: suprocess.Process = await suprocess.create_subprocess_exec(*rsync_commands,
                                                                     stderr=asyncio.subprocess.PIPE,
                                                                     stdout=asyncio.subprocess.PIPE,
                                                                     )

    stdout, stderr = await sync.communicate()
    returncode: int = sync.returncode
    if returncode != 0:
        err_msg: bot_api.BatchSyncErrMsg = bot_api.BatchSyncErrMsg(returncode=returncode,
                                                                   stdout=stdout.decode(),
                                                                   stderr=stderr.decode())
        data = bot_api.BatchSyncError(err_info=err_msg)
    else:
        data = bot_api.BatchSyncComplete()
        print(stdout)
        print(stderr)

    return data


async def sync_batch(ad_specific_dir: Path, completion_msg: BatchCompleted, sync_context: SyncContext) -> int:

    # check if already synced
    print(completion_msg)
    try:
        batch = Batch.objects.get(#location__state_name="alex-ubuntu",
                                  start_timestamp=completion_msg.run_id,
                                  server_container=completion_msg.hostname,
                                  )
        print("Batch found not synced")
        print(batch)
    except Batch.DoesNotExist:
        print("batch does not exist")
        return -1
        raise Exception("Batch does not exist")
    if batch.synced:
        print("Batch is already synced")
        print("Please implement cleanup with check")
        #raise Exception("batch is already synced")
    # Preserve external ip recorded
    completion_msg.external_ip = batch.external_ip

    server_user = sync_context.storage_user
    dest_host = sync_context.storage_hostname
    dest_directory = sync_context.storage_base_dir
    src_base = sync_context.ad_base_dir


    result = await sync_directory(src=ad_specific_dir,
                                  sync_context=sync_context)

    msg = bot_api.BatchSynced(batch_info=completion_msg,
                              sync_result=result)

    print("sync msg: ")
    print(msg.to_json())

    # send sync event

    publisher: pubsub_v1 = sync_context.publisher

    publisher.publish(sync_context.publisher_topic, data=msg.to_json().encode())

    if msg.data.kind == bot_api.BatchSyncStatus.ERROR:
        print("ERROR: ", msg.to_json())
        return -1
    elif msg.data.kind == bot_api.BatchSyncStatus.COMPLETE:
        print("No problems")
        return 0


async def sync_single(request: aiohttp.web_request.Request):

    sync_context: SyncContext = request.app["sync_context"]
    src_base = sync_context.ad_base_dir
    text: dict = await request.json()
    ad_specific_path = Path(text["directory_to_sync"])

    completion_msg = text["completion_msg"]
    complete: bot_api.BatchCompleted = bot_api.BatchCompleted.from_json(completion_msg)

    sync_context = request.app["sync_context"]

    await sync_batch(completion_msg=complete, sync_context=sync_context)

    return web.Response(text="DONE")



def construct_directory_from_completion_msg(msg: bot_api.BatchCompleted) -> Path:

    return Path(msg.location) / f"{msg.host_hostname}#{msg.hostname}" / f"{msg.host_hostname}#{msg.hostname}" / f"{msg.timestamp}"


async def start_background_tasks(app):
    app['periodic_sync'] = app.loop.create_task(background_print())
    app["wait_shutdown"] = app.loop.create_task(wait_for_shutdown(app))

async def periodic_sync():
    result = await suprocess.create_subprocess_shell("crond")
    print(result)

def count_json_files(ad_dir: pathlib.Path) -> int:
    return ilen(ad_dir.glob("*.json"))


def deterimine_ad_format_version(ad_dir: pathlib.Path) -> Optional[int]:
    """ad_dir: The parent directory where the ad files are stored (xml, json)"""

    # Is it version 2+?
    try:
        with ad_dir.joinpath("ad_format_version").open("r") as f:
            version = int(f.read())
            return version
    except FileNotFoundError:
        # If not assume version 1
        return 1


def reconstruct_completion_msg(ad_dir: pathlib.Path) -> BatchCompleted:
    """ad_dir: parent directory directly containing xml/json ad files
    returns a `BatchCompleted` message object"""
    version: int = deterimine_ad_format_version(ad_dir)

    # Version 3 of ad format we collect ad urls in .txt
    if version == 3:
        ad_count = count_txt_files(ad_dir)
    # Version 2 of ad format Google stores ad info in .json
    elif version == 2:
        ad_count = count_json_files(ad_dir)
    # Version 1 of ad format Google stored ad info in .xml vast responses
    elif version == 1:
        ad_count = count_xml_files(ad_dir)
    else:
        raise NotImplemented(f"version: `{version}` not handled")

    non_ads = count_non_ad_requests(ad_dir)
    try:
        first_html = first(html_files(ad_dir))
        external_ip = extract_ip_from_html_player(first_html.open())
        if external_ip == "0.0.0.0":
            print(first_html)
    except ValueError:
        # No html files present
        external_ip = "0.0.0.0"
        print(ad_dir)
    total_requests = ad_count + non_ads
    last_request = last_request_time(ad_dir)
    ad = AdStorage(ad_dir)
    completion_msg = BatchCompleted(status=BatchCompletionStatus.COMPLETE, hostname=ad.hostname, run_id=ad.run_id,
                                    external_ip=external_ip, bots_in_batch=8,
                                    requests=total_requests, host_hostname=ad.host_hostname,
                                    location=ad.location, ads_found=ad_count, timestamp=last_request)
    return completion_msg


async def reconstruct_all(request: aiohttp.web_request.Request):
    text = await request.text()
    print(text)
    sync_context: SyncContext = request.app["sync_context"]

    # sync all batches regardless of age
    force_sync = request.get("force_sync", "false")
    if force_sync in ["false", "False", "0"]:
        force_sync = False
    elif force_sync in ["true", "True", "1"]:
        force_sync = True
    else:
        print(f"invalid option for force_sync: {force_sync}")
        force_sync = False

    base_dir = sync_context.ad_base_dir
    print(sync_context.ad_base_dir)

    new_data_dirs = [x.parent for x in base_dir.glob("*/*#*/*/*.log")]
    data_dir: Path

    for data_dir in new_data_dirs:
        msg = reconstruct_completion_msg(data_dir)
        print(f"completion_msg: {msg.to_json()}")


        if not batch_is_old(msg) and not force_sync:
            print("Skipping batch, not old enough")
            continue
        print("directory syncing:", data_dir)
        result = await sync_batch(ad_specific_dir=data_dir, completion_msg=msg, sync_context=sync_context)
        print(result)

        if result < 0:
            print("error")
        else:
            print("no error")

    return web.Response(text="OK")


def init_server() -> web.Application:

    # start application
    app = web.Application()
    app.add_routes([web.post("/", test_check),
                    web.get("/test", test_check),
                    web.post("/test", test_post),
                    web.post("/single", sync_single),
                    web.get("/reconstruct_all", reconstruct_all),
                    ])


    dest_host = os.environ["STORAGE_HOST"]
    dest_directory = Path(os.environ["STORAGE_DIR"])
    server_user = os.environ["STORAGE_USER"]
    src_base = Path(os.environ["SYNC_DATA_DIR"])
    app["socket_file"] = os.environ["SYNC_SOCKET"]

    try:
        project_id: str = os.environ["GOOGLE_CLOUD_PROJECT"]
    except KeyError:
        raise ValueError("GOOGLE_CLOUD_PROJECT not set in env")

    try:
        credential_location: str = os.environ["GOOGLE_APPLICATION_CREDENTIALS"]
    except KeyError:
        raise ValueError("GOOGLE_APPLICATION_CREDENTIALS were not set")
    try:
        topic_batch: str = os.environ["NOTIFY_TOPIC"]
    except KeyError as e:
        raise KeyError("NOTIFY_TOPIC must be set, choices (batch_production or development)")

    publisher = pubsub_v1.PublisherClient()
    topic: str = publisher.topic_path(project_id, topic=topic_batch)

    app["sync_context"] = SyncContext(ad_base_dir=src_base,
                storage_base_dir=dest_directory,
                storage_hostname=dest_host,
                storage_user=server_user,
                publisher=publisher,
                publisher_topic=topic,)


    server_address = app["socket_file"]
    print("server address:", server_address)

    # Make sure the socket does not already exist
    try:
        os.unlink(server_address)
    except OSError:
        if os.path.exists(server_address):
            raise

    # Create a UDS socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(server_address)

    app["sock"] = sock

    return app


if __name__ == "__main__":
    app = init_server()
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sync_server.settings")
    import django

    django.setup()
    from processor.models import Batch

    web.run_app(app, sock=app["sock"])
