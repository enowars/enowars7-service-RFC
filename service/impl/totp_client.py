import time
import hashlib
import hmac


class User:

    def __init__(self,
                 username: str,
                 secret_phrase: str
                 ):
        self.username = username
        self.secret_phrase = secret_phrase
        self.client = None

class Totp_Client:

    def __init__(self,
                 num_digits: int=6):

        self.secret_key = ""
        self.init_time = time.time()
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
        time_diff = int(time.time() - self.init_time) # floor the diff or fllor individually?
        steps = int(time_diff/self.timestep)
        self.timestep_counter = steps
        return




def create_user(allusers, servers):
    username = input("enter the username: ")
    secret_phrase = input("enter secret phrase: ")
    server_init = int(input("init-time: "))
    user1 = None
    if not secret_phrase:
        user1 = User(username)
    else:
        user1 = User(username, secret_phrase)

    user1.generate_shared_secret()
    server = totp_server.Totp()
    allusers.update({username: user1})
    servers.update({username:server})
def main():
#    importlib.import_module("totp_server")
 #   importlib.import_module("totp_client")
    servers = dict()
    allusers = dict()

    while True:
        try:
            action = input("enter an action:\n\t c - create User \n\t o - calculate otp and have it validated.\n-->")
            if not action:
                continue
            elif action == "c":
                create_user(allusers, servers)
                print("users: ", allusers)
            elif action == "o":
                username = input("username in question: ")
                userx = allusers[username]
                if userx == None:
                    print("failure, user does not exist")
                    continue
                userx.calculate_current_timestep_count()
                user_otp = userx.generate_otp(userx.secret_key, userx.timestep_counter)
                print(user_otp)
                serverx = servers[username]
                res = serverx.validate_otp(user_otp, userx.secret_key)
                if res:
                    print("successfully genererated the OTP")
                else:
                    print("failure")
            else:
                continue

        except Exception as e:
            print(e)

if __name__ == "__main__":
    main()
