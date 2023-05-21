import time
import hashlib
import hmac
from datetime import timezone
import datetime

class Totp:
    """A class for generating and validating TOTPs"""

    def __init__(self,
                 num_digits: int=6,
                 timestep_counter: int=0,
                 init_time: int=int(time.time())
                 ):

        if num_digits > 10 or num_digits < 6:
            raise ValueError("The number of digits for the OTP must be between 6 and 10")
        self.num_digits = num_digits
        self.timestep_counter = timestep_counter
        self.timestep = 30
        self.init_time = init_time #unix time in UTC

        self.digest = hashlib.sha1
        self.throttle = 42 #refuse connections after this many failed auth attempts
        self.lookahead = 2
        return

#RFC4226 statest that the shaed secret must be of at least 128 bits, preferably 160 bits
#IDEA: user can provide their own key, and iof they do not, then a shared secret key is generated

    def generate_shared_secret(self, user_phrase: str=""):
        secret = user_phrase
        if not user_phrase:
            secret = "Hier könnte Ihr Geheimnis stehen!"
        hashed_secret = hashlib.sha256(secret.encode())
        return hashed_secret.digest()

    def generate_otp(self, shared_secret: str, timestep_counter: int):
        # for HOTP: HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
        #returns 20 byte string
        #using timestep could be a vuln because then the output is always identical hmac_result = hmac.new(self.generate_shared_secret(), bytes(timestep), self.digest)
        hmac_result = hmac.new(shared_secret, bytes(self.timestep_counter), self.digest)
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

    def validate_otp(self, user_otp: int, shared_secret: str):
        self.calculate_current_timestep_count()
        server_otp = self.generate_otp(shared_secret, self.timestep_counter)
        print(f"userotp: {user_otp} serverotp: {server_otp}")
        if user_otp == server_otp:
            return True
        else:
            match, offset = self.check_lookahead_window(user_otp, shared_secret)
            self.resynchronize(offset)
            return match

    def check_lookahead_window(self, user_otp: int, shared_secret: str):
        offset = self.lookahead+1
        match = False

        for i in range(1, self.lookahead+1):
            if user_otp == self.generate_otp(shared_secret, self.timestep_counter+i):
                offset = i
                match = True
                break

        return match, offset

    #TODO
    def resynchronize(self, offset: int):
        if offset > self.lookahead:
            print("Out-of-sync! Could not find valid otp wihtin  lookahead window, resyncing.")
        else:
            print("Out-of-sync! Still found valid otp within lookahead.")
        return

