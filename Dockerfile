FROM python:3.8

RUN apt-get update && apt-get install -y rsync && rm -rf /var/lib/apt/lists/* /var/cache/apt/*
RUN python3 -m pip install --no-cache-dir setuptools

USER root
RUN chmod -R 777 /root
ENV HOME=/root
WORKDIR /root
RUN mkdir app

# Set google project id and credential file
RUN mkdir /root/creds
ENV GOOGLE_CLOUD_PROJECT=cyads-203819
ENV GOOGLE_APPLICATION_CREDENTIALS=/root/creds/Cyads-pubsub.json

COPY requirements.txt .
RUN python3 -m pip install --no-cache-dir -r requirements.txt

COPY . app
CMD ["python3", "./app/app.py"]
