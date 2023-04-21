import requests as rq
import argparse
import json

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="This script ist supposed to retrieve information about the usage of Matrix accounts.\n" +
                                        "Running this script could be useful to find abandoned accounts.")
    login = parser.add_mutually_exclusive_group(required=True)

    login.add_argument('-t', '--token', help="Provide an admin-token to access the Matrix API.")
    login.add_argument('-l', '--login', help="Provide a username and password to be used in authentication process.", type=str)

    parser.add_argument('-s', '--matrix_server', help="Provide the home address of your matrix matrix_server.", required=True)
    parser.add_argument('-a', '--ascending', help="List the accounts in ascending order => most recently online first", default=False, action='storeTrue', required=False)
    #parser.add_argument('-v', '--matrix_version', help="Specify the Matrix API version you wanna access", required=False)

    return parser


def get_users():
    return rq.get(url=f"https://{matrix_server}/_synapse/admin/v2/users", headers=headers)


def get_access_token(usr, pwd, is_admin) -> str:
    url = f"https://{matrix_server}/_matrix/client/r0/login"
    admin_param = f"?admin={is_admin}".lower()  # lower(), bc string-rep. of python bools are usually capitalized

    response = rq.get(url=(url + admin_param), auth=(usr, pwd))

    if response.status_code != 200:
        print(f"Fehler: Die API-Anfrage ist fehlgeschlagen.\nExit Code: {response.status_code}\nJSON response: {response.json()}")
        exit()

    return response.json()["access_token"]


def create_global_vars(args) -> None:
    token = args.token
    login = args.login

    global matrix_server
    matrix_server = args.server

    global ascending
    ascending = args.ascending

    global headers
    if token is not None:
        headers = {"Authorization": f"Bearer {token}"}
    elif login is not None:
        login = login.split(sep=" ")
        headers = {"Authorization": f"Bearer {get_access_token(login[0], login[1])}"}


def main():
    parser = create_parser()
    args = parser.parse_args()

    create_global_vars(args)

    collected_users = json.load(get_users().json())
    accounts = [account for account in collected_users]
    
    # sorts the accounts by the last_active_ago timestamps, default: least recently online to most recently online
    accounts.sort(key=lambda x: int(x.last_active_ago), reverse=(not ascending))

    print(accounts)


if __name__ == "__main__":
    main()
