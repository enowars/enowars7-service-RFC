FROM python:3.8.16-buster

WORKDIR /tmp 
COPY ./requirements.txt .
RUN python3 -m pip install -r requirements.txt

WORKDIR /service
COPY . .

RUN chmod +x entrypoint.sh
