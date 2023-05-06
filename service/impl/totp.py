import time
import hashlib
import hmac

class Totp:
    """A class for generating and validating TOTPs"""

    def __init__(self):
        self.lookahead_window = 2
        self.num_digits = 6
        self.throttle = 42 #refuse connections after this many failed auth attempts
        self.init_time = int(time.time()) #unix time in UTC

        # timestep count is an int that is based on )the time that has past
        # the value increases every thirty seconds (the timestep)
        #note: the counter has to be somewhat synchronized between client and server
        self.timestep_counter = 0 #with every full 30 seconds, the counter increases
        self.timestep = 30

        self.digest = hashlib.sha1
        return

#RFC4226 statest that the shaed secret must be of at least 128 bits, preferably 160 bits
#IDEA: user can provide their own key, and iof they do not, then a shared secret key is generated

    def generate_shared_secret(self):
        secret = "my personal secret"
        hashed_secret = hashlib.sha256(secret.encode())
        return hashed_secret.digest()

    def validate_otp(self):
       return

    def generate_otp(self, timestep: int):
        # for HOTP: HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
        self.calculate_current_timestep_count()
        #returns 20 byte string
#using timestep could be a vuln because then the output is always identical        hmac_result = hmac.new(self.generate_shared_secret(), bytes(timestep), self.digest)
        hmac_result = hmac.new(self.generate_shared_secret(), bytes(self.timestep_counter), self.digest)
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


class User:
    def __init__(self, username):
        self.username = username
        self.secret_key = None



def main():
    device = Totp()
    while True:
        try:
            username = input("enter the username: ")
            user1 = User(username)
        except Exception as e:
            print(e)
        print(device.generate_otp(0))

if __name__ == "__main__":
    main()
