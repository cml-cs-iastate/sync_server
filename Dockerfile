FROM testcyads/base_os:0.2

RUN groupadd bot_group
RUN groupadd sudo
RUN useradd -rm -d /home/bot -s /bin/bash -g root -G sudo,bot_group -u 1000 bot
RUN chmod -R 777 /home/bot
RUN chown bot /home/bot -R

#RUN apt-get update && apt-get install -y --no-install-recommends git rsync ssh ca-certificates openconnect openvpn

RUN pacman -Sy && pacman -S --noconfirm rsync openssh ca-certificates

USER bot
WORKDIR /home/bot
RUN mkdir app
COPY requirements.txt .
RUN pip3 install --user --no-cache-dir -r requirements.txt
USER root
RUN pacman -S --noconfirm python-mysqlclient
USER bot
#RUN pip3 install --user --no-cache-dir mysqlclient

USER root
#RUN apt-get remove -y git
RUN pacman -R --noconfirm git
RUN pacman -Scc --noconfirm
USER bot
# install bot_api from git




#RUN echo "*/1 * * * * /usr/local/bin/send_to_server.sh" >> /etc/crontabs/bot

RUN mkdir -p /home/bot/.ssh
COPY --chown=bot:bot_group ./id_rsa /home/bot/.ssh/id_rsa
# ssh key not visible to "others"
RUN chmod 400 /home/bot/.ssh/id_rsa
COPY --chown=bot:bot_group ./id_rsa.pub /home/bot/.ssh/id_rsa.pub
#RUN ssh-keyscan cyads.misc.iastate.edu >> /home/bot/.ssh/known_hosts

# Set google project id and credential file
ENV GOOGLE_CLOUD_PROJECT="cyads-203819"
ENV GOOGLE_APPLICATION_CREDENTIALS="/home/bot/creds/Cyads-pubsub.json"
RUN mkdir /home/bot/creds
COPY --chown=bot:bot_group ./Cyads_pubsub.json /home/bot/creds/Cyads-pubsub.json
RUN mkdir -p app
COPY . app

CMD ["python3", "/home/bot/app/app.py"]
