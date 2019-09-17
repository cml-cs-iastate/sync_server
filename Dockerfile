FROM testcyads/base_os:0.3

# Delete selenium userid and home dir
RUN userdel -r seluser
RUN groupadd bot_group
RUN useradd -rm -d /home/bot -s /bin/bash -g root -G sudo,bot_group -u 1000 -o bot
USER 1000:1000
RUN if [ "$(whoami)" != "bot" ]; then echo " user: $(whoami)" is not 'bot'; exit 2; fi
RUN chmod -R 777 /home/bot
RUN chown bot /home/bot -R
ENV HOME=/home/bot


WORKDIR /home/bot
RUN mkdir app
COPY requirements.txt .
RUN python3.7 -m pip install --user --no-cache-dir -r requirements.txt
# install bot_api from git


RUN mkdir -p /home/bot/.ssh
COPY --chown=bot:bot_group ./id_rsa /home/bot/.ssh/id_rsa
# ssh key not visible to "others"
RUN chmod 400 /home/bot/.ssh/id_rsa
COPY --chown=bot:bot_group ./id_rsa.pub /home/bot/.ssh/id_rsa.pub

#RUN ssh-keyscan cyads.misc.iastate.edu >> /home/bot/.ssh/known_hosts
COPY --chown=bot:bot_group ./known_hosts /home/bot/.ssh/known_hosts

# Set google project id and credential file
ENV GOOGLE_CLOUD_PROJECT=cyads-203819
ENV GOOGLE_APPLICATION_CREDENTIALS=/home/bot/creds/Cyads-pubsub.json
RUN mkdir /home/bot/creds
COPY --chown=bot:bot_group ./Cyads_pubsub.json /home/bot/creds/Cyads-pubsub.json
RUN mkdir -p app
COPY . app

CMD ["python3.7", "/home/bot/app/app.py"]
