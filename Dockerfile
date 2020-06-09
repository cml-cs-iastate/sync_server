FROM testcyads/base_os:0.3

USER root
RUN chmod -R 777 /root
ENV HOME=/root

WORKDIR /root
RUN mkdir app
COPY requirements.txt .
RUN python3.7 -m pip install --user --no-cache-dir -r requirements.txt


RUN mkdir -p /root/.ssh
COPY --chown=root:root ./id_rsa /root/.ssh/id_rsa
# ssh key not visible to "others"
RUN chmod 400 /root/.ssh/id_rsa
COPY --chown=root:root ./id_rsa.pub /root/.ssh/id_rsa.pub

#RUN ssh-keyscan cyads.misc.iastate.edu >> /home/bot/.ssh/known_hosts
COPY --chown=root:root ./known_hosts /root/.ssh/known_hosts

# Set google project id and credential file
ENV GOOGLE_CLOUD_PROJECT=cyads-203819
ENV GOOGLE_APPLICATION_CREDENTIALS=/root/creds/Cyads-pubsub.json
RUN mkdir /root/creds
COPY --chown=root:root ./Cyads_pubsub.json /root/creds/Cyads-pubsub.json
RUN mkdir -p app
COPY . app

CMD ["python3.7", "./app/app.py"]
