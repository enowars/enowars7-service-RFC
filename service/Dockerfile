FROM python:3.8.16-buster

RUN apt update && apt install -y nginx sqlite3
COPY ./nginx.conf /etc/nginx/nginx.conf

WORKDIR /tmp 
COPY ./requirements.txt .
RUN python3 -m pip install -r requirements.txt

WORKDIR /service
COPY . /service

RUN chmod +x /service/entrypoint.sh
RUN chmod +x /service/cleanup.sh
ENTRYPOINT /service/entrypoint.sh
