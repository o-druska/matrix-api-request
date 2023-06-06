# Oskar Druska, 2023

import requests as rq
import logging
import argparse
import json

logger = logging.getLogger()
logger.addHandler(logging.StreamHandler())


def create_parser() -> argparse.ArgumentParser:
    """
    creates an ArgumentParser object which will be used to analyze given command line arguments
        Input: None
        Return: argparse.ArgumentParser
    """
    parser = argparse.ArgumentParser(
        description="This script is supposed to retrieve information about the usage of Matrix accounts.\n" +
                    "Running this script could be useful to find abandoned accounts.")

    # User has to sepcify exactly one argument, either an access token
    # XOR username and password to retrieve a token via this script
    login = parser.add_mutually_exclusive_group(required=True)

    login.add_argument('-t', '--token',
                       help="Provide an admin-token to access the Matrix API. " +
                       "--token and --login are mutually exclusive.",
                       type=str)
    login.add_argument('-l', '--login',
                       help="Provide a username and password to be used in authentication process. " +
                       "--token and --login are mutually exclusive.",
                       nargs=2, type=str)

    parser.add_argument('-s', '--server',
                        help="Provide the home address of your matrix server.",
                        required=True, type=str)
    parser.add_argument('-a', '--ascending',
                        help="List the accounts in descending order => most recently online first. " +
                        "The sorting criteria is a timestamp corresponding to a date in milliseconds after the unix epoch. " +
                        "Therefore the higher the timestamp the more recent the activity",
                        default=False, action='store_true', required=False)
    parser.add_argument('-d', '--debug',
                        help="Debug mode; will print more verbose debug "
                             "output",
                        default=False, action='store_true', required=False)

    return parser


def check_response(response: rq.Response) -> None:
    """
    This function is a wrapper to check the status_code of
    the given rq.Response object.

    Has no special prupose except decluttering functions,
    which make calls via requests.
        Input:   reponse: rq.Response
        Return:  None
        Failure: exit program
    """
    if response.status_code != 200:
        logger.warning("Warning:\tThe API request failed..\n" +
                     f"status code:\t{response.status_code}\n" +
                     f"JSON response:\t{response.json()}\n" +
                     f"URL:\t\t{response.url}")
        exit(1)


def get_users(server: str, headers: dict) -> dict:
    """
    Uses requests to call Matrix API to get a list of registered user objects
    including a last-seen timestamp in unix-milliseconds.
    The timestamp marks the date and time after the unix epoch on which
    the session has been most recently active.
        Input:  str: server
                dict: data
        Return: dict
    """

    url = f"https://{server}/_synapse/admin/v2/users"
    logger.debug("get_users URL:\t\t" + str(url))

    # Dev note:
    # Fun fact: requests apparently uses logging for debug purposes.
    # Creating a logging object and setting its level to DEBUG will also
    # affect request debug output
    logger.debug("\n")
    response = rq.get(url=url,headers=headers)
    logger.debug("\n")

    check_response(response)

    return response.json()


def get_access_token(server: str, username: str, password: str) -> str:
    """
    Takes a type and (username, password) or (token) to retrieve an access token via API call.
    _login_type is the login method. The API provides login via token too, but that did
    not work as expected and usr_pwd login is totally sufficient for this purpose.
    m.login.password will therefore be hardcoded in here.
        Input:  
                str: server
                str: username
                str: password
        Return: str: access_token
        Failure: if token call not successful, then exit program with err_code = 1.
    """
    # Listing the registered users is only possible with admin access

    url = f"https://{server}/_matrix/client/r0/login"
    logger.debug("login URL:\t\t" + str(url))

    body = {'type': "m.login.password", 'user': username, 'password': password}
    logger.debug("login body:\t\t" + str(body))

    logger.debug("\n")
    response = rq.post(url=url,
                      data=json.dumps(body))    # rq.request should be able to serialize a dict into JSON
                                                # but apparently the API cannot handle that:
                                                # {'errcode': 'M_NOT_JSON', 'error': 'Content not JSON.'}
                                                # That's why I use json.dumps() here.
    logger.debug("\n")

    check_response(response)

    # TODO: check, if returning dictionary looks like we expect it to.

    return response.json()['access_token']


def create_request_header(token: str) -> dict:
    """
    Takes a token string and creates a header dictionary as JSON string
    Scheme: {Authorization: Bearer <token>}
        Input: token: str
        Return: dict[str, str]
    """

    headers = {"Authorization": f"Bearer {token}"}

    return headers


def main() -> None:
    args = create_parser().parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    logger.debug("parsed args:\t\t" + str(args))
    logger.debug("Server:\t\t\t" + str(args.server))

    if args.login:
        args.token = get_access_token(server=args.server,
                                      username=args.login[0],
                                      password=args.login[1])

    logger.debug("processed token:\t" + str(args.token))

    headers = create_request_header(args.token)
    logger.debug("Created headers:\t" + str(headers))

    matrix_users = get_users(args.server, headers)

    logger.debug(matrix_users)
    accounts = list(matrix_users)
    logger.debug(accounts)

    # sorts the accounts by the last_active_ago timestamps, default: least recently online to most recently online
    accounts.sort(key=lambda x: int(x.last_active_ago),
                  reverse=(not args.ascending))
    print(accounts)


if __name__ == "__main__":
    main()
