from __future__ import annotations
from dataclasses import dataclass
from typing import Iterator, List, Optional, Union
import io
import re
from aiohttp import web
import aiohttp
import socket
import bot_api
from aiohttp import web_request, web_response
import asyncio.subprocess as suprocess
import asyncio
from google.cloud import pubsub_v1, pubsub
import os
import json

import pathlib
from pathlib import Path
from more_itertools import first, ilen
from bot_api import (BatchSyncComplete, BatchSyncStatus, BatchSynced, BotEvents, BatchCompleted, BatchCompletionStatus)
from datetime import datetime
from django.core.exceptions import ObjectDoesNotExist

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sync_server.settings")

from sentry_sdk import capture_event, capture_exception, capture_message

import shutil
import logging

import traceback
import urllib

routes = web.RouteTableDef()
from logging import getLogger
logger = getLogger(__name__)

class DumpFile:
    def __init__(self, filename: pathlib.Path):
        (self.bot_name,
         self.try_num,
         self.ad_seen_at,
         self.video_watched) = filename.stem.split("#")


class DumpDir:

    def __init__(self, ad_dir: pathlib.Path):
        # The absolute path of the specific batch of ads
        self.path = ad_dir
        self.run_id = int(self.path.name)
        (self.host_hostname, self.container_hostname) = self.path.parents[0].name.split("#")
        self.location = self.path.parents[1].name

    def __repr__(self):
        return self.path.as_posix()

    @classmethod
    def from_completion_msg(cls, completion_msg: BatchCompleted, base_dir: Path) -> DumpDir:
        relative_inner_ad_path: Path = construct_directory_from_completion_msg(completion_msg)
        abs_ad_path = base_dir.joinpath(relative_inner_ad_path).absolute()
        return cls(ad_dir=abs_ad_path)


@dataclass()
class SyncContext:
    # directory where ads are stored in
    ad_unsynced_local_base_dir: Path
    # hostname/ip to move ads to
    dest_storage_hostname: str
    # username to login to the server in
    dest_storage_user: str
    # base directory to copy ads into
    dest_storage_base_dir: Path
    # pubsub client
    publisher: pubsub_v1
    # pubsub topic
    publisher_topic: str


def count_txt_files(ad_dir: pathlib.Path) -> int:
    """Ad format v3"""
    return ilen(ad_dir.glob("Bot*.txt"))


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
                return int(DumpFile(abs_ad_filepath).ad_seen_at)
            except (AttributeError, ValueError) as e:
                # Possible file corruption
                print("FILE CORRUPTION IN FOLLOWING DIRECTORY")
                print(abs_ad_filepath)
                continue
        else:
            return -1
    except FileNotFoundError:
        version = determine_ad_format_version(ad_dir)
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
                ad = DumpFile(file)
            except Exception as e:
                print("DDDD", e, file)
                raise e
            if int(ad.ad_seen_at) > latest:
                latest = int(ad.ad_seen_at)
        return latest


def messages_from_file(file: pathlib.Path) -> List[BatchSynced]:
    with file.open() as f:
        messages = f.readlines()
    return [BatchSynced.from_json(message) for message in messages]


def batch_is_old_using_dumpdir(dump_dir: DumpDir) -> bool:
    start_time = dump_dir.run_id
    return batch_is_old(start_time)


def batch_is_old_using_completion_msg(completion_msg: BatchCompleted) -> bool:
    start_time = completion_msg.run_id
    return batch_is_old(start_time)


def batch_is_old(start_time: int) -> bool:
    age_of_batch = datetime.now() - datetime.utcfromtimestamp(start_time)
    hours_threshold = 24
    batch_age_hours = age_of_batch.days * 24 + age_of_batch.seconds / 60 / 60
    return batch_age_hours >= hours_threshold


async def test_check(request: aiohttp.web_request.Request):
    return web.Response(text="OK")


async def sync_directory(src: Path, sync_context: SyncContext) -> Union[BatchSyncComplete, bot_api.BatchSyncError]:
    rsync_commands = ["rsync", "-a", "--relative",
                      # example: /home/alex/github/dumps/./louisiana/node12.misc.iastate.edu#e6ede031d296/1564364031
                      ####src_base##########   ######################src################################
                      f"{sync_context.ad_unsynced_local_base_dir.as_posix()}/./{src.relative_to(sync_context.ad_unsynced_local_base_dir).as_posix()}",
                      f"{sync_context.dest_storage_user}@{sync_context.dest_storage_hostname}:{sync_context.dest_storage_base_dir.as_posix()}"]
    logger.info("rsync commands:", str(rsync_commands))
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
        print("rsync stdout:", stdout)
        print("rsync stderr:", stderr)
    else:
        data = bot_api.BatchSyncComplete()

    return data


async def sync_batch(ad_specific_dir: Path, completion_msg: BatchCompleted, sync_context: SyncContext):
    """Syncs a batch from a completion msg"""
    print("original completion msg:", completion_msg)

    try:
        batch = Batch.objects.get(location__state_name=completion_msg.location,
                                  start_timestamp=completion_msg.run_id,
                                  server_hostname=completion_msg.host_hostname,
                                  server_container=completion_msg.hostname,
                                  )
    except Batch.DoesNotExist as e:
        # Create new record of batch to sync
        batch = Batch(location__state_name=completion_msg.location,
                      start_timestamp=completion_msg.run_id,
                      server_hostname=completion_msg.host_hostname,
                      server_container=completion_msg.hostname,
                      )
        batch.save()
        print("Creating batch which does not exist with completion msg:", completion_msg)
    except Batch.MultipleObjectsReturned as e:
        # use 1st batch
        batch = Batch.objects.filter(location__state_name=completion_msg.location,
                                  start_timestamp=completion_msg.run_id,
                                  server_hostname=completion_msg.host_hostname,
                                  server_container=completion_msg.hostname,
                                  )[0]

    except Exception as e:
        raise e
    # check if already synced
    if batch.synced:
        print("Batch is already synced")
        print("Please implement cleanup with check")
        # raise Exception("batch is already synced")
    # Preserve external ip recorded
    completion_msg.external_ip = batch.external_ip
    print("Updated completion msg with IP")
    print(completion_msg)

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
        raise Exception("Error syncing batch: ", msg)
    elif msg.data.kind == bot_api.BatchSyncStatus.COMPLETE:
        print("No problems")


async def sync_single(request: aiohttp.web_request.Request):
    sync_context: SyncContext = request.app["sync_context"]
    src_base = sync_context.ad_unsynced_local_base_dir
    completion_msg: dict = await request.json()
    # Note, fix bot_api.from_json to take str, and a dict
    complete: bot_api.BatchCompleted = bot_api.BatchCompleted.from_json(json.dumps(completion_msg))
    ad_specific_dir: DumpDir = DumpDir.from_completion_msg(base_dir=sync_context.ad_unsynced_local_base_dir,
                                                           completion_msg=complete)
    app.logger.info(f"syncing batch path: {ad_specific_dir.path.as_posix()}")

    print("syncing batch", complete.to_json())
    try:
        await sync_batch(completion_msg=complete, sync_context=sync_context,
                         ad_specific_dir=ad_specific_dir.path)
    except Exception as e:
        print("Error when syncing:", e)

    return web.Response(text="DONE")


def construct_directory_from_completion_msg(msg: bot_api.BatchCompleted) -> Path:
    return (Path(msg.location)
            .joinpath(f"{msg.host_hostname}#{msg.hostname}")
            .joinpath(f"{msg.run_id}")
            )


@routes.get("/delete_synced_dirs")
async def delete_dirs(request: aiohttp.web_request):
    try:
        sync_context: SyncContext = request.app["sync_context"]

        base_dir = sync_context.ad_unsynced_local_base_dir

        errors = False
        for log_file_data_dir in base_dir.glob("*/*#*/*/*.log"):
            data_dir = log_file_data_dir.parent
            with sentry_sdk.configure_scope() as scope:
                dump_dir = DumpDir(data_dir)

                try:
                    # Check Batch in db marked as synced before deletion
                    # non-async django, may stall application.

                    # Use 1st batch duplicate for determining if synced
                    try:
                        batch = Batch.objects.filter(location__state_name=dump_dir.location,
                                              start_timestamp=dump_dir.run_id,
                                              server_hostname=dump_dir.host_hostname,
                                              server_container=dump_dir.container_hostname,
                                              )[0]
                    except IndexError:
                        print(f"{dump_dir}, is not a batch")
                        continue

                except Exception as e:
                    errors = True
                    traceback.print_exc()
                    continue

                    # WARNING: Any batch marked as synced is assumed to have been properly synced to a known location.
                if batch.synced:
                    # Delete the directory
                    print("Deleting:", dump_dir.path.as_posix())

                    # Sanity check to make sure not deleting outside base ad dir
                    if sync_context.ad_unsynced_local_base_dir not in dump_dir.path.parents:
                        print("tried to delete outside of ad dir:", dump_dir.path.as_posix())
                        break
                    try:
                        shutil.rmtree(dump_dir.path, ignore_errors=False)
                    except PermissionError:
                        print(f"Are you root? Failed to delete directory: {dump_dir.path}")
                        raise
                    print("deleted:", dump_dir.path.as_posix())
    except Exception as e:
        traceback.print_exc()
        return web.Response(text=str(e), status=500)

    if errors:
        return web.Response(text="errors deleting 1+ directories", status=500)
    else:
        return web.Response(text="ok delete", status=200)


async def background_delete(app):
    server_address = app["socket_file"]

    while True:
        print("Starting background delete")
        try:
            conn = aiohttp.UnixConnector(path=server_address)
            timeout = aiohttp.ClientTimeout(total=600)
            async with aiohttp.ClientSession(connector=conn, raise_for_status=True) as session:
                # localhost substitutes for the socket file
                async with session.get(f"http://localhost/delete_synced_dirs", timeout=timeout) as resp:
                    print("delete resp:", resp.status, "delete text:", await resp.text())
            await asyncio.sleep(60 * 60)
        except asyncio.CancelledError:
            break
        except Exception as e:
            print("exception when deleting:", e)
            traceback.print_exc()
            raise e

async def periodic_sync_unprocessed(app):
    """Periodically check for unsynced data. Sync it."""
    server_address = app["socket_file"]
    while True:
        print("Starting background sync unprocessed")
        try:
            conn = aiohttp.UnixConnector(path=server_address)
            timeout = aiohttp.ClientTimeout(total=600)
            async with aiohttp.ClientSession(connector=conn, raise_for_status=True) as session:
                # localhost substitutes for the socket file
                async with session.get(f"http://localhost/sync_unprocessed", timeout=timeout) as resp:
                    pass
            await asyncio.sleep(60 * 30)
        except asyncio.CancelledError:
            break
        except asyncio.TimeoutError:
            print("Timeout 1hr syncing data: ", timeout)
        except Exception as e:
            traceback.print_exc()
            raise e from None


async def start_background_tasks(app):
    loop = asyncio.get_running_loop()
    app['periodic_delete'] = loop.create_task(background_delete(app))
    #app['periodic_sync'] = loop.create_task(periodic_sync_ping(app))
    app['periodic_sync_unprocessed'] = loop.create_task(periodic_sync_unprocessed(app))


async def cleanup_background_tasks(app):
    app["periodic_delete"].cancel()
    #app["periodic_sync"].cancel()
    app["periodic_sync_unprocessed"].cancel()

    await app["periodic_delete"]
    #await app["periodic_sync"]
    await app["periodic_sync_unprocessed"]


def count_json_files(ad_dir: pathlib.Path) -> int:
    return ilen(ad_dir.glob("*.json"))


def determine_ad_format_version(ad_dir: pathlib.Path) -> int:
    """ad_dir: The parent directory where the ad files are stored (xml, json)"""

    # Is it version 2+?
    try:
        with ad_dir.joinpath("ad_format_version").open("r") as f:
            version = int(f.read())
            return version
    except FileNotFoundError:
        # If not assume version 1
        return 1


def reconstruct_completion_msg(dump_dir: DumpDir) -> BatchCompleted:
    """ad_dir: parent directory directly containing xml/json ad files
    returns a `BatchCompleted` message object"""

    # Hack for no metadata about number of bots ran
    try:
        batch = Batch.objects.get(location__state_name=dump_dir.location,
                                  start_timestamp=dump_dir.run_id,
                                  server_hostname=dump_dir.host_hostname,
                                  server_container=dump_dir.container_hostname,
                                  )
        external_ip = batch.external_ip
        num_bots = batch.total_bots
    except Batch.DoesNotExist as e:
        logfile = next(dump_dir.path.glob("bots_*.log"))
        external_ip = "0.0.0.0"

        with logfile.open() as f:
            for line in f:
                jline = json.loads(line)
                try:
                    num_bots = int(jline["num_bots"])
                    print("batch:", dump_dir, "has", num_bots, "bot(s)")
                    break
                except KeyError:
                    continue

    version: int = determine_ad_format_version(dump_dir.path)

    # Version 3 of ad format we collect ad urls in .txt
    if version == 3:
        ad_count = count_txt_files(dump_dir.path)
    # Version 2 of ad format Google stores ad info in .json
    elif version == 2:
        ad_count = count_json_files(dump_dir.path)
    # Version 1 of ad format Google stored ad info in .xml vast responses
    elif version == 1:
        ad_count = count_xml_files(dump_dir.path)
    else:
        raise NotImplemented(f"version: `{version}` not handled")

    non_ads = count_non_ad_requests(dump_dir.path)
    total_requests = ad_count + non_ads
    last_request = last_request_time(dump_dir.path)

    # Count size of the video list bots watched
    with dump_dir.path.joinpath("political_videos.csv").open() as f:
        video_list_size = sum(1 for _ in f)
    completion_msg = BatchCompleted(status=BatchCompletionStatus.COMPLETE, hostname=dump_dir.container_hostname,
                                    run_id=dump_dir.run_id,
                                    external_ip=external_ip, bots_in_batch=num_bots,
                                    requests=total_requests, host_hostname=dump_dir.host_hostname,
                                    location=dump_dir.location, ads_found=ad_count, timestamp=last_request,
                                    video_list_size=video_list_size,
                                    )
    return completion_msg


async def reconstruct_all(request: aiohttp.web_request.Request):
    _ = await request.text()
    sync_context: SyncContext = request.app["sync_context"]

    # sync all batches regardless of age
    force_sync = request.rel_url.query.get("force_sync", "false")
    if force_sync in ["false", "False", "0"]:
        force_sync = False
    elif force_sync in ["true", "True", "1"]:
        force_sync = True
    else:
        print(f"invalid option for force_sync: {force_sync}")
        force_sync = False

    base_dir = sync_context.ad_unsynced_local_base_dir

    new_data_dirs = [x.parent for x in base_dir.glob("*/*#*/*/*.log")]
    data_dir: Path

    err = False
    for data_dir in new_data_dirs:
        try:
            dump_dir = DumpDir(ad_dir=data_dir)
            msg = reconstruct_completion_msg(dump_dir)
            print(f"completion_msg: {msg.to_json()}")

            if not batch_is_old_using_completion_msg(msg) and not force_sync:
                print("Skipping batch, not old enough", dump_dir.path)
                continue
            print("directory syncing:", data_dir)
            result = await sync_batch(ad_specific_dir=data_dir, completion_msg=msg, sync_context=sync_context)
            print(result)
        except Exception as e:
            err = True
            continue
    if err:
        return web.Response(text="An error occurred syncing some batch(s)")
    else:
        return web.Response(text="OK Reconstruct and sync complete")


def ad_dir_from_parts(base_dir: Path, location: str, host_hostname: str, container_hostname: str,
                      start_time: str) -> DumpDir:
    ad_dir = base_dir.joinpath(location).joinpath(f"{host_hostname}#{container_hostname}").joinpath(start_time)
    return DumpDir(ad_dir=ad_dir)


async def notify_of_untracked_batches(app: web.Application):
    """Notify server of any missed batches which were not tracked"""
    sync_context: SyncContext = app["sync_context"]
    unsynced_dirs = [x.parent for x in sync_context.ad_unsynced_local_base_dir.glob("*/*#*/*/*.log")]
    for unsynced_dir in unsynced_dirs:
        dump_dir = DumpDir(unsynced_dir)
        completion_msg = reconstruct_completion_msg(dump_dir)


@routes.get('/sync/batch/{state}/{host_container}/{start_time}')
async def sync_from_url(request: aiohttp.web_request.Request):
    location = request.match_info["state"]
    server_hostname, container_hostname = request.match_info["host_container"].split("#")
    start_time = request.match_info["start_time"]
    sync_context: SyncContext = request.app["sync_context"]
    base_ad_dir = sync_context.ad_unsynced_local_base_dir
    ad_dir: DumpDir = ad_dir_from_parts(base_ad_dir, location=location, host_hostname=server_hostname,
                                        container_hostname=container_hostname, start_time=start_time)

    completion_msg = reconstruct_completion_msg(ad_dir)
    await sync_batch(ad_specific_dir=ad_dir.path, completion_msg=completion_msg, sync_context=sync_context)

    resp = {"location": location, "server_hostname": server_hostname, "container_hostname": container_hostname,
            "start_time": start_time}

    return web.json_response(resp)


def init_server() -> web.Application:
    stdio_handler = logging.StreamHandler()
    stdio_handler.setLevel(logging.DEBUG)
    _logger = logging.getLogger('aiohttp.access')
    _logger.addHandler(stdio_handler)
    _logger.setLevel(logging.DEBUG)

    # start application
    app = web.Application(logger=_logger)

    app.add_routes([web.post("/", test_check),
                    web.get("/test", test_check),
                    web.post("/single", sync_single),
                    web.get("/reconstruct_all", reconstruct_all),
                    web.get("/sync_unprocessed", sync_unprocessed),
                    ])
    app.add_routes(routes)

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

    app["sync_context"] = SyncContext(ad_unsynced_local_base_dir=src_base,
                                      dest_storage_base_dir=dest_directory,
                                      dest_storage_hostname=dest_host,
                                      dest_storage_user=server_user,
                                      publisher=publisher,
                                      publisher_topic=topic, )

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
    os.chmod(server_address, 0o777)

    app["sock"] = sock

    return app


def true_str(value: str) -> Optional[bool]:
    if value in ["false", "False", "0"]:
        return False
    elif value in ["true", "True", "1"]:
        return True
    else:
        return None


async def sync_unprocessed(request: aiohttp.web_request.Request):
    _ = await request.text()
    sync_context: SyncContext = request.app["sync_context"]

    force_sync = request.rel_url.query.get("force_sync", "false")
    force_sync = true_str(force_sync)
    if force_sync is None:
        force_sync = False

    base_dir = sync_context.ad_unsynced_local_base_dir

    new_data_dirs = [x.parent for x in base_dir.glob("*/*#*/*/*.log")]
    request.app.logger.debug(f"base_dir={base_dir.as_posix()}, unscanned dirs: {new_data_dirs}")
    data_dir: Path

    err = False
    for data_dir in new_data_dirs:
        request.app.logger.debug(f"Scanning directory:, batch_dir={data_dir.as_posix()}")
        dump_dir = DumpDir(data_dir)
        marked_done = dump_dir.path.joinpath("done").exists()
        try:
            if not marked_done and not batch_is_old_using_dumpdir(dump_dir) and not force_sync:
                request.app.logger.info(f"Skipping batch, not old enough, batch_dir={data_dir.as_posix()}")
                continue
            request.app.logger.info(f"Marking directory as done with batch, batch_dir={dump_dir.path.as_posix()}")
            data_dir.joinpath("done").touch()
            request.app.logger.info(f"Marked directory as done with batch, batch_dir={data_dir.as_posix()}")

            completion_msg = reconstruct_completion_msg(dump_dir)

            request.app.logger.info(f"directory syncing:, batch_dir={data_dir.as_posix()}")
            result = await sync_directory(src=data_dir, sync_context=sync_context)
            request.app.logger.info(f"sync result, result={result}, batch_dir={data_dir.as_posix()}")
            result = await sync_directory(src=data_dir, sync_context=sync_context)
            if result == bot_api.BatchSyncError:
                request.app.logger.error(f"error syncing batch:, result={result}")
                continue

            msg = bot_api.BatchSynced(batch_info=completion_msg,
                                      sync_result=result)

            request.app.logger.info(f"sync msg:, msg={msg.to_json()}")

            # send sync event
            publisher: pubsub_v1 = sync_context.publisher
            publisher.publish(sync_context.publisher_topic, data=msg.to_json().encode("utf-8"))
            request.app.logger.info(f"published sync msg")
        except Exception as e:
            err = True
            request.app.logger.exception(e, extra={"batch_dir": data_dir.as_posix()})
            continue
    if err:
        return web.Response(text="An error occurred syncing some batch(s)")
    else:
        return web.Response(text="OK sync complete")


if __name__ == "__main__":
    # Initialize sentry_sdk for error handling
    import sentry_sdk

    sentry_sdk.init("https://2e6c116bc9d341b7afd8f349a9be0a6b@sentry.io/1554000")

    app = init_server()
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sync_server.settings")
    import django

    django.setup()
    from processor.models import Batch

    # start background tasks
    app.on_startup.append(start_background_tasks)
    # graceful shutdown of background tasks
    app.on_cleanup.append(cleanup_background_tasks)

    web.run_app(app, sock=app["sock"])
