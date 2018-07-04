FROM alpine:latest

RUN mkdir -p /var/cache/apk
RUN apk add --update --no-cache rsync openssh ca-certificates
RUN apk add --no-cache python3
RUN apk add --no-cache python3-dev
RUN apk add --no-cache gcc
RUN apk add --no-cache g++
RUN apk add --no-cache make
RUN apk add --no-cache musl-dev
RUN pip3 install aiohttp --no-cache-dir
RUN pip3 install google-cloud-pubsub --no-cache-dir

RUN apk del python3-dev gcc g++ make musl-dev


RUN apk add --no-cache git
# install bot_api from git
RUN pip3 install git+git://github.com/cml-cs-iastate/bot_api@master

RUN apk del git
# Needed by google pubsub
RUN apk add --no-cache libstdc++

RUN addgroup -g 1000 -S botgroup
RUN adduser -u 1000 -S bot_sync -G botgroup

COPY --chown=bot_sync:botgroup ./send_to_server.sh /usr/local/bin/send_to_server.sh
RUN mkdir -p /home/bot_sync
RUN chmod -R 777 /home/bot_sync
RUN chown bot_sync /home/bot_sync -R
RUN chmod +x /usr/local/bin/send_to_server.sh

RUN echo "*/1 * * * * /usr/local/bin/send_to_server.sh" >> /etc/crontabs/bot_sync

USER bot_sync
RUN mkdir -p /home/bot_sync/.ssh
COPY --chown=bot_sync:botgroup ./id_rsa /home/bot_sync/.ssh/id_rsa
# ssh key not visible to "others"
RUN chmod 400 /home/bot_sync/.ssh/id_rsa
COPY --chown=bot_sync:botgroup ./id_rsa.pub /home/bot_sync/.ssh/id_rsa.pub
RUN ssh-keyscan db.misc.iastate.edu >> /home/bot_sync/.ssh/known_hosts

# Set google project id and credential file
ENV GOOGLE_CLOUD_PROJECT="cyads-203819"
ENV GOOGLE_APPLICATION_CREDENTIALS="/home/bot_sync/creds/Cyads-pubsub.json"
COPY --chown=bot_sync:botgroup ./Cyads_pubsub.json /home/bot_sync/creds/Cyads-pubsub.json
COPY --chown=bot_sync:botgroup ./sync_server.py /usr/local/bin/sync_server.py

CMD ["python3", "/usr/local/bin/sync_server.py"]
