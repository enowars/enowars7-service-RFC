import time

class Totp:
    """A class for generating and validating TOTPs"""

    def __init__(self):
        self.lookahead_window = 2
        self.num_digits = 6
        self.throttle = 42 #refuse connections after this many failed auth attempts
        self.init_time = int(time.time()) #unix time in UTC
        self.timestep_count = 0 #with every full 30 seconds, the counter increases
        self.timestep = 30

    def generate_shared_secret():
        return

    def validate_otp():
       return

    def generate_otp():
        # for HOTP: HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
        return

    def hmac_sha1():
        return

    def truncate():
        return

    def calculate_current_timestep_count():
        time_diff = int(time.time() - self.init_time) # floor the diff or fllor individually?
        steps = int(time_diff/timestep)
        #here we could set the counter  = steps    
        return


class User:
    def __init__(self, username):
        self.username = username
        self.secret_key = None



def main():
    while True:
        try:
            username = input("enter the username: ")
            user1 = User(username)
        except Exception as e:
            print(e)


if __name__ == "__main__":
    main()
