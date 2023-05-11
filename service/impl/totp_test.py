import importlib
from managedServiceProvider import totp_server
from totp_client import *

def create_user(allusers, servers):
    username = input("enter the username: ")
    secret_phrase = input("enter secret phrase: ")
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
