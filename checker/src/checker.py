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

from enochecker3 import (
    ChainDB,
    Enochecker,
    ExploitCheckerTaskMessage,
    GetflagCheckerTaskMessage,
    MumbleException,
    PutflagCheckerTaskMessage,
)
from enochecker3.utils import FlagSearcher, assert_equals, assert_in
from httpx import AsyncClient

"""

"""
SERVICE_PORT = 4242
checker = Enochecker("OnlyBlog", SERVICE_PORT)
app = lambda: checker.app
"""

"""

class Totp_Client:
    def __init__(self,
                 init_time: int=int(time.time()),
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
                self.secret_phrase = "Hier könnte ihr Geheimnis stehen"
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


async def register_user(task, client):
    username = ''.join(secrets.choice(string.ascii_letters+string.digits) for i in range(10))
    password = ''.join(secrets.choice(string.ascii_letters+string.digits) for i in range(25))
    secret = ''.join(secrets.choice(string.ascii_letters+string.digits) for i in range(25))

    logger.debug(f"New user registration. Username: {username}, Password: {password}")
    url = "http://" + task.address + ':' + str(SERVICE_PORT)} + "/auth/register"
    formdata = {"username": username, "password": password, "secret phrase": secret}
    r = await client.post(url, json=formdata)
    assert_equals(r.status_code, 302, "Registration error in register user function.")
    return username, password, secret

async def login_user(task, client, username, password):
    logger.debug(f"Logging in user: {username}, with password: {password}")
    url =  "http://" + task.address + ':' + str(SERVICE_PORT)} + "/auth/login"
    formdata = {"username": username, "password": password}
    r = await client.post(url, json=formdata)
    assert_equals(r.status_code, 302, "Login Error in login_user function.")
    return r.cookies

async def create_blogpost(cookies, flag):
    title = ''.join(secrets.choice(string.ascii_letters+string.digits) for i in range(25))
    body = flag
    private = "True"
    formdata = {"title": title, "body": body, "private": private}
    url =  "http://" + task.address + ':' + str(SERVICE_PORT)} + "/create"
    r = await client.post(url, json=formdata, cookies=cookies)

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
    username, password, secret = register_user(task, client)
    cookies = login_user(task, client, username, password)
    title, postid = create_blogpost(cookies, flag)

    await db.set("nec_info", (username, password, secret, title, postid))
    attackinfo = {"title": title, "postid": postid}
    return json.dumps(attackinfo)

@checker.getflag(0)
async def getflag_zero(
    task: GetflagCheckerTaskMessage
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
    cookie = login_user(task, client, userdata['username'], userdata['password'])
    url = "http://" + task.address + str(SERVICE_PORT) + "/auth/accessblogpost/" + userdata['postid']
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

@checker.explpoit(0)
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

    username, password, secret = register_user(task, client)
    cookies = login_user(task, client, username, password)

    url = "http://" + task.address + str(SERVICE_PORT) + "/"
    r = await client.get(url, cookies=cookie)

    time = find_params(r, username, postid)

    return
