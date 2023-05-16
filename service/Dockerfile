FROM ubuntu:22.04
RUN apt update && apt install python3-pip sqlite

WORKDIR /tmp 
COPY ./requirements.txt .
RUN python3 -m pip install -r requirements.txt

WORKDIR /service
COPY . .

RUN chmod +x entrypoint.sh
