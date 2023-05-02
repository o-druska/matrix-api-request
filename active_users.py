# Oskar Druska, 2023

import requests as rq
import logging
import argparse
import json

logger = logging.getLogger()

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
    login.add_argument('-d', '--dummy', help="Makes a dummy call to the API login; API will return a dummy access token", action='store_true', default=False)

    parser.add_argument('-s', '--matrix_server', help="Provide the home address of your matrix matrix_server.", required=True)
    parser.add_argument('-a', '--ascending', help="List the accounts in ascending order => most recently online first", default=False, action='store_true', required=False)

    # not sure how the API version is important to our efforts.
    # the current versions are hardcoded based on examples I found on the Matrix API documentation.
    # parser.add_argument('-v', '--matrix_version', help="Specify the Matrix API version you wanna access", required=False)

    return parser

def make_request_call(request_method: str, url: str, headers: dict) -> dict:
    response = rq.request(method=request_method, url=url, headers=headers)

    if response.status_code != 200:
        logger.error("Fehler: Die API-Anfrage ist fehlgeschlagen.\n" +
                     f"Exit Code: {response.status_code}\n" +
                     f"JSON response: {response.json()}\n" +
                     f"URL: {url}")
        exit(1)

    return response.json()


def get_users(matrix_server: str, headers: dict) -> dict:
    '''
    Uses requests to call Matrix API to get a list of registered user objects.
        Input:  str: matrix_server
                dict: headers
        Return: dict
    '''

    url = f"https://{matrix_server}/_synapse/admin/v2/users"

    return make_request_call('GET', url, headers)


def get_access_token(_login_type: str, matrix_server: str, **kwargs) -> str:
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
    # Listing the registered users is only possible with admin access

    print(kwargs)

    _usr = kwargs.get('usr', None)
    _pwd = kwargs.get('pwd', None)
    _token = kwargs.get('token', None)

    url = f"https://{matrix_server}/_matrix/client/r0/login"

    match _login_type:
        case "m.login.password":
            d = {'type': _login_type, 'user': _usr, 'password': _pwd}
        case "m.login.token":
            d = {'type': _login_type, 'token': _token}
        case "m.login.dummy":
            d = {'type' : _login_type}
        case _:
            logger.error(f"Fehler: Die angegebene Login Variante ist nicht gültig: {_login_type}\n" +
                         "Mögliche Loginvarianten sind: " + str(['m.login.password', 'm.login.token', 'm.login.dummy']))
            exit(1)

    d = json.dumps(d)

    return make_request_call('POST', url, d)['access_token']


def create_request_header(token: str) -> str:
    '''
    Takes a token string and creates a header dictionary as JSON string
    Scheme: {Authorization: Bearer <token>}
        Input: str
        Return: str
    '''

    headers = json.dumps({"Authorization": f"Bearer {token}"})
    return headers


def main() -> None:
    args = create_parser().parse_args()
    matrix_server = args.matrix_server

    if args.dummy:
        args.token = get_access_token(_login_type="m.login.dummy", matrix_server=matrix_server)
    elif args.login:
        args.token = get_access_token(_login_type="m.login.password", matrix_server=matrix_server, usr=args.login[0], pwd=args.login[1])
    else:
        args.token = get_access_token(_login_type="m.login.token", matrix_server=matrix_server, token=args.token)

    headers = create_request_header(args.token)
    print(headers)

    matrix_users = get_users(matrix_server, headers)
    accounts = list(matrix_users)

    # sorts the accounts by the last_active_ago timestamps, default: least recently online to most recently online
    accounts.sort(key=lambda x: int(x.last_active_ago), reverse=(not args.ascending))
    print(accounts)


if __name__ == "__main__":
    main()
