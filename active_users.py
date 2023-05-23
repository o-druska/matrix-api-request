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
        description="This script ist supposed to retrieve information about the usage of Matrix accounts.\n" +
                    "Running this script could be useful to find abandoned accounts.")

    # User has to sepcify exactly one argument, either an access token
    # XOR username and password to retrieve a token via this script
    login = parser.add_mutually_exclusive_group(required=True)

    login.add_argument('-t', '--token',
                       help="Provide an admin-token to access the Matrix API.")
    login.add_argument('-l', '--login',
                       help="Provide a username and password to be used in authentication process.",
                       nargs=2, type=str)

    parser.add_argument('-s', '--matrix_server',
                        help="Provide the home address of your matrix matrix_server.",
                        required=True)
    parser.add_argument('-a', '--ascending',
                        help="List the accounts in ascending order => most recently online first",
                        default=False, action='store_true', required=False)
    parser.add_argument('-d', '--debug',
                        help="Debug mode; will print more verbose debug "
                             "output",
                        default=False, action='store_true', required=False)

    # not sure how the API version is important to our efforts.
    # the current versions are hardcoded based on examples I found on the Matrix API documentation.
    # parser.add_argument('-v', '--matrix_version', help="Specify the Matrix API version you wanna access", required=False)

    return parser


def make_request_call(request_method: str, url: str, **kwargs) -> dict:
    """
    Incapsualtes a common rq.request() call by adding a status code check and
    error messages
    :param request_method HTTP verb
    :param url URL to call on
    :param data python dictionary containing information to be send in the request-body
    :param headers python dict containing to-be-transmitted headers
    """

    '''
    Dev note:
    This function exists to encapsulate the request call with a status_code check.
    I am not satisfied by this way of basically using a wrapper function bc ideally I'd have to double-parse
    all the kwargs of rq.request.
    Is there a way to check the status_code without having to manually do that after each request call?
    (I'm thinking of some kind of overwrite/overload)
    '''

    data = kwargs.get('data', None)
    headers = kwargs.get('headers', None)

    logger.debug("HTTP method:\t\t" + str(request_method))
    logger.debug("URL to call:\t\t" + str(url))
    logger.debug("Data in request body:\t" + str(data))
    logger.debug("Request headers:\t" + str(headers))

    logger.debug("\n")

    # Dev note:
    # Fun fact: requests apparently uses logging for debug purposes.
    # Creating a logging object and setting its level to DEBUG will also
    # affect request debug output
    response = rq.request(method=request_method,
                          url=url,
                          data=json.dumps(data),  # rq.request should be able to serialize a dict into JSON
                                                  # but apparently the API cannot handle that:
                                                  # {'errcode': 'M_NOT_JSON', 'error': 'Content not JSON.'}
                                                  # That's why I use json.dumps() here.
                          headers=headers)

    logger.debug("\n")

    if response.status_code != 200:
        logger.error("Fehler:\t\tDie API-Anfrage ist fehlgeschlagen.\n" +
                     f"Exit Code:\t{response.status_code}\n" +
                     f"JSON response:\t{response.json()}\n" +
                     f"URL:\t\t{url}")
        exit(1)

    return response.json()


def get_users(matrix_server: str, headers: dict) -> dict:
    """
    Uses requests to call Matrix API to get a list of registered user objects.
        Input:  str: matrix_server
                dict: data
        Return: dict
    """

    url = f"https://{matrix_server}/_synapse/admin/v2/users"
    logger.debug("get_users URL:\t\t" + str(url))

    return make_request_call('GET', url, headers=headers)


def get_access_token(_login_type: str, matrix_server: str, **kwargs) -> str:
    """
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
        Failure: if token call not successful, then exit program with err_code = 1.
    """
    # Listing the registered users is only possible with admin access

    logger.debug("get_access_token kwargs " + str(kwargs))

    _usr = kwargs.get('usr', None)
    _pwd = kwargs.get('pwd', None)
    _token = kwargs.get('token', None)

    url = f"https://{matrix_server}/_matrix/client/r0/login"
    logger.debug("login url:\t\t" + str(url))

    # dev note: I tried to put the login types into an array and match-case with that,
    # but matching with a variable is not that trivial in Python.
    # The API is limited to three login types, therefore I think the amount of
    # hard-code is excusable.
    match _login_type:
        case "m.login.password":
            d = {'type': _login_type, 'user': _usr, 'password': _pwd}
        case "m.login.token":
            d = {'type': _login_type, 'token': _token}

        # Has not sufficently been tested bc documentation suggest that a dummy-login will only pretend to return a valid token.
        # Dummy token won't be usable for any authentication.
        case "m.login.dummy":
            d = {'type': _login_type}

        case _:
            logger.error(
                f"Fehler: Die angegebene Login Variante ist nicht gültig: {_login_type}\n" +
                "Mögliche Loginvarianten sind: " + str(['m.login.password', 'm.login.token', 'm.login.dummy']))
            exit(1)

    logger.debug("login body:\t\t" + str(d))

    return make_request_call('POST', url, data=d)['access_token']


def create_request_header(token: str) -> dict:
    """
    Takes a token string and creates a header dictionary as JSON string
    Scheme: {Authorization: Bearer <token>}
        Input: str
        Return: str
    """

    headers = {"Authorization": f"Bearer {token}"}

    return headers


def main() -> None:
    args = create_parser().parse_args()
    matrix_server = args.matrix_server

    if args.debug:
        logger.setLevel(logging.DEBUG)

    logger.debug("parsed args:\t\t" + str(args))
    logger.debug("Server:\t\t\t" + str(matrix_server))

    if args.login:
        args.token = get_access_token(_login_type="m.login.password",
                                      matrix_server=matrix_server,
                                      usr=args.login[0], pwd=args.login[1])
    else:
        # Dev note:
        # requesting a token via API will return a different one than the one you could
        # get via client>Settings>Help:Advanced
        # That's why I decided to request a token, even if one has been specified by the user
        args.token = get_access_token(_login_type="m.login.token",
                                      matrix_server=matrix_server,
                                      token=args.token)

    logger.debug("processed token:\t" + str(args.token))

    headers = create_request_header(args.token)
    logger.debug("Created headers:\t" + str(headers))

    matrix_users = get_users(matrix_server, headers)
    accounts = list(matrix_users)

    # sorts the accounts by the last_active_ago timestamps, default: least recently online to most recently online
    accounts.sort(key=lambda x: int(x.last_active_ago),
                  reverse=(not args.ascending))
    print(accounts)


if __name__ == "__main__":
    main()
