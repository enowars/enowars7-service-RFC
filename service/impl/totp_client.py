import time
import hashlib
import hmac


class User:
    def __init__(self,
                 username: str,
                 secret_phrase: str=""):

        self.username = username
        self.secret_phrase = secret_phrase
        self.secret_key = self.generate_shared_secret()
        self.init_time = time.time()
        self.timestep = 30
        self.timestep_counter = 0

    def generate_shared_secret(self):
        if not self.secret_phrase:
            self.secret_phrase = "Hier könnte ihr Geheimnis stehen"
        secret_key_tmp = hashlib.sha256(self.secret_phrase.encode())
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
