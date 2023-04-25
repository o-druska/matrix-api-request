# Oskar Druska, 2023

import requests as rq
import logging
import argparse
import json


def create_parser() -> argparse.ArgumentParser:
    '''
    creates an ArgumentParser object which will be used to analyze given command line arguments
        Input: None
        Return: argparse.ArgumentParser
    '''
    parser = argparse.ArgumentParser(description="This script ist supposed to retrieve information about the usage of Matrix accounts.\n" +
                                                 "Running this script could be useful to find abandoned accounts.")

    # User has to sepcify exactly one argument, either an access token
    # XOR username and password to retrieve a token via this script
    login = parser.add_mutually_exclusive_group(required=True)

    login.add_argument('-t', '--token', help="Provide an admin-token to access the Matrix API.")
    login.add_argument('-l', '--login', help="Provide a username and password to be used in authentication process.", nargs=2, type=str)

    parser.add_argument('-s', '--matrix_server', help="Provide the home address of your matrix matrix_server.", required=True)
    parser.add_argument('-a', '--ascending', help="List the accounts in ascending order => most recently online first", default=False, action='store_true', required=False)

    # not sure how the API version is important to our efforts.
    # the current versions are hardcoded based on examples I found on the Matrix API documentation.
    # parser.add_argument('-v', '--matrix_version', help="Specify the Matrix API version you wanna access", required=False)

    return parser


def get_users() -> rq.Response:
    '''
    uses requests to call Matrix API to get a list of registered user objects.
    Status code of the returning Response object will determine success.
        Input: None
        Return: request.Response
    '''

    url = f"https://{matrix_server}/_synapse/admin/v2/users"
    response = rq.get(url=url, headers=headers)

    if response.status_code != 200:
        logger.error("Fehler: Die API-Anfrage ist fehlgeschlagen.\n" +
                     f"Exit Code: {response.status_code}\n" +
                     f"JSON response: {response.json()}\n" +
                     f"URL: {url}")
        exit(1)

    return response.json()


def login(_login_type: str, _usr: str, _pwd: str, _token: str) -> str:
    '''
    Takes a type and (username, password) or (token) to retrieve an access token via API call.
    _login_type is the login method. Has to be retrieved via a GET call to the login page of the matrix server
    m.login.password -> usr_pwd login scheme (will use usr_pwd to login)
    m.login.token -> login via access token (will use token to login)
    m.login.dummy -> API does not verify authenticity (debug purposes)
        Input:  str: _login_type
                str: _usr
                str: _pwd
                str: _token
        Return: str: access_token
        Failure: if token call not successful, then exit program.
    '''
    # Listing the registered users is not possible without admin access

    url = f"https://{matrix_server}/_matrix/client/r0/login"

    match _login_type:
        case "m.login.password":
            d = {'type': _login_type, 'user': _usr, 'password': _pwd}
        case "m.login.token":
            d = {'type': _login_type, 'token': _token}
        case "m.login.dummy":
            pass  # necessity not gaugable yet
        case _:
            logger.error(f"Fehler: Die angegebene Login Variante ist nicht gültig: {_login_type}\n" +
                         "Mögliche Loginvarianten sind: " + str(['m.login.password', 'm.login.token', 'm.login.dummy']))
            exit(1)

    d = json.dumps(d)
    response = rq.post(url=url, data=d)

    if response.status_code != 200:
        logger.error("Fehler: Die API-Anfrage ist fehlgeschlagen.\n" +
                     f"Exit Code: {response.status_code}\n" +
                     f"JSON response: {response.json()}\n" +
                     f"URL: {url}")
        exit(1)

    return response.json()["access_token"]


def create_request_header(token: str) -> dict:
    '''
    Takes a token string and creates a header dictionary
    Scheme: {Authorization: Bearer <token>}
        Input: str
        Return: dict
    '''

    headers = {"Authorization": f"Bearer {token}"}
    return headers


def main() -> None:
    global matrix_server
    global headers
    global logger

    logger = logging.getLogger()

    args = create_parser().parse_args()
    matrix_server = args.matrix_server

    if args.login:  # overwrite args.token with token gained from usr_pwd login
        args.token = login(_login_type="m.login.password", _usr=args.login[0], _pwd=args.login[1])
    else:
        args.token = login(_login_type="m.login.token", token=args.token)

    headers = create_request_header(args.token)

    collected_users = json.load(get_users().json())
    accounts = [account for account in collected_users]

    # sorts the accounts by the last_active_ago timestamps, default: least recently online to most recently online
    accounts.sort(key=lambda x: int(x.last_active_ago), reverse=(not args.ascending))
    print(accounts)


if __name__ == "__main__":
    main()


# admin_param = f"?admin={is_admin}".lower()  # lower(), bc string-rep. of python bools are usually capitalized
