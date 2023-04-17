import requests as rq
import argparse
import json

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="This script ist supposed to retrieve information about the usage of Matrix accounts.\n" +
                                        "Running this script could be useful to find abandoned accounts.")
    parser.add_argument('-t', '--token', help="Provide an admin-token to access the Matrix API.", required=True)
    parser.add_argument('-s', '--server', help="Provide the home address of your matrix server.", required=True)
    parser.add_argument('-a', '--ascending', help="List the accounts in ascending order => most recently online first", default=False, action='storeTrue')

    return parser

def get_profile_info(username, domain):
    return rq.get(url= f"https://{server}/_matrix/client/v3/profile/@{username}:{domain}", headers=headers)


def get_presence_status(username, domain):
    return rq.get(url= f"https://{server}/_matrix/client/v3/presence/@{username}:{domain}/status", headers=headers)

def get_users():
    return rq.get(url= f"https://{server}/_synapse/admin/v2/users", headers=headers)


def main():
    parser = create_parser()
    args = parser.parse_args()

    global token
    token = args.token

    global server
    server = args.server

    global headers
    headers = {"Authorization": f"Bearer {token}"}

    ascending = args.ascending

    username = "oskar.d"
    domain = "inm7.de"

    print(get_profile_info(username=username, domain=domain).json())
    print(get_presence_status(username=username, domain=domain).json())

    collected_users = json.load(get_users().json())
    accounts = []

    for account in collected_users.users:
        accounts.pushback(account)
    
    accounts.sort(key=lambda x: int(x.last_active_ago), reverse=(not ascending)) # sorts the accounts by the last_active_ago timestamps, default: least recently online to most recently online

    print(accounts)


if __name__ == "__main__":
    main()
