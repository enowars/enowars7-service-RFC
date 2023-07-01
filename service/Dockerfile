FROM python:3.8.16-buster

RUN apt update && apt install -y nginx sqlite3
COPY ./config/nginx.conf /etc/nginx/nginx.conf

WORKDIR /tmp 
COPY ./config/requirements.txt .
RUN python3 -m pip install -r requirements.txt

WORKDIR /service
COPY . /service

RUN chmod +x /service/scripts/entrypoint.sh
RUN chmod +x /service/scripts/cleanup.sh
ENTRYPOINT /service/scripts/entrypoint.sh
