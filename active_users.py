import requests as rq
import argparse

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="This script ist supposed to retrieve information about the usage of Matrix accounts.\n" +
                                        "Running this script could be useful to find abandoned accounts.")
    parser.add_argument('-t', '--token', help="Provide an admin-token to access the Matrix API.", required=True)
    parser.add_argument('-s', '--server', help="Provide the home address of your matrix server.", required=True)

    return parser

def get_profile_info(username, domain):
    return rq.get(url= f"https://{server}/_matrix/client/v3/profile/@{username}:{domain}", headers=headers)


def get_presence_status(username, domain):
    return rq.get(url= f"https://{server}/_matrix/client/v3/presence/@{username}:{domain}/status", headers=headers)


def main():
    parser = create_parser()
    args = parser.parse_args()

    global token
    token = args.token

    global server
    server = args.server

    global headers
    headers = {"Authorization": f"Bearer {token}"}

    username = "oskar.d"
    domain = "inm7.de"

    print(get_profile_info(username=username, domain=domain).json())
    print(get_presence_status(username=username, domain=domain).json())


if __name__ == "__main__":
    main()
