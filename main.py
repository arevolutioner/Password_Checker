import requests
import hashlib
import sys
from pathlib import Path

file = Path("passord.txt").read_text()


def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check the API and try again")
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


# check password if it exists in API response
# and converts it to sha1
def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


# receives the arguments/passwords from a file and
def main_func(args):
    password = args
    count = pwned_api_check(password)
    if count:
        print(f"{password} was found {count} times, you should change your password")
    else:
        print(f"{password}was not found. Carry on! is Good! ")
    return "done!"
    # for password in args:
    #     count = pwned_api_check(password)
    #     if count:
    #         print(f"{password} was found {count} times, you should change your password")
    #     else:
    #         print(f"{password} is Good! ")


if __name__ == "__main__":
#   main_func(sys.argv[1:])
    main_func(file)
