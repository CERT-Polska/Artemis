"""
OWASP OFFAT Tester Utils Module
"""
from http import client as http_client
import ssl
# from sys import exc_info
# from typing import Optional
# from asyncio import run
# from asyncio.exceptions import CancelledError
# from re import search as regex_search


# from .post_test_processor import PostRunTests


def is_host_up(openapi_parser, ssl_verify: bool = True) -> bool:
    '''checks whether the host from openapi doc is available or not.
    Returns True is host is available else returns False'''
    tokens = openapi_parser.host.split(':')
    use_ssl = False
    match len(tokens):
        case 1:
            host = tokens[0]
            port = 443 if openapi_parser.http_scheme == 'https' else 80
        case 2:
            host = tokens[0]
            port = int(tokens[1])
        case _:
            return False

    if openapi_parser.http_scheme == 'https':
        use_ssl = True

    host = host.split('/')[0]

    match port:
        case 443:
            use_ssl = True
            proto = http_client.HTTPSConnection
        case _:
            if use_ssl:
                proto = http_client.HTTPSConnection
            else:
                proto = http_client.HTTPConnection
    try:
        if not use_ssl:
            conn = proto(host=host, port=port, timeout=5)
        else:
            if ssl_verify:
                conn = proto(host=host, port=port, timeout=5)
            else:
                conn = proto(
                    host=host,
                    port=port,
                    timeout=5,
                    context=ssl._create_unverified_context())
        conn.request('GET', '/')
        res = conn.getresponse()
        return res.status in range(200, 499)
    except Exception:
        return False


def reduce_data_list(data_list: list[dict] | str) -> list[dict] | str:
    """
    Reduces a list of dictionaries to only include 'name' and 'value' keys.

    Args:
        data_list (list[dict] | str): The input data list to be reduced.

    Returns:
        list[dict] | str: The reduced data list with only 'name' and 'value' keys.

    """
    if isinstance(data_list, list):
        return [
            {'name': param.get('name'), 'value': param.get('value')}
            for param in data_list
        ]

    return data_list
