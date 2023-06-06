FROM python:3.8.16-buster

RUN apt update && apt install -y nginx
COPY ./nginx.conf /etc/nginx/nginx.conf

WORKDIR /tmp 
COPY ./requirements.txt .
RUN python3 -m pip install -r requirements.txt

WORKDIR /service
COPY . .

RUN chmod +x entrypoint.sh
ENTRYPOINT /service/entrypoint.sh
