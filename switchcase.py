#!/usr/bin/env python

import argparse
import requests
import json
import logging
import re
import ast


def get_hosts(server_url, auth_pair, ssl_check=True):
    logger = logging.getLogger(__name__)
    print("Retrieving host list")
    logger.info("Retrieving host list")
    server_target = '/'.join(
        [
            server_url,
            "host?format=json"
        ]
    )
    http_get_host = requests.get(
        server_target,
        verify=ssl_check,
        auth=auth_pair,
        params={'format': 'json'}
    )

    logger.info('Header: {0}'.format(http_get_host.headers))
    logger.info('Request: {0}'.format(http_get_host.request))
    logger.info("Status code: {0}".format(
        http_get_host.status_code
    ))

    if http_get_host.status_code != 200 \
       and http_get_host.status_code != 201:
        print("Status code: {0}".format(http_get_host.status_code))

    return json.loads(http_get_host.text)


def check_hostname(regex, server_name):
    if regex.match(server_name):
        return True
    else:
        return False


def update_host(server_endpoint, data_payload, auth_pair, ssl_check=True):
    logger = logging.getLogger(__name__)
    http_patch = requests.patch(
        server_endpoint,
        data=json.dumps(data_payload),
        verify=ssl_check,
        auth=auth_pair,
        headers={'content-type': 'application/json'}
    )

    logger.info('Header: {0}'.format(http_patch.headers))
    logger.info('Request: {0}'.format(http_patch.request))
    logger.info("Status code: {0}".format(
        http_patch.status_code
    ))
    logger.info('Text: {0}'.format(http_patch.text))

    # TODO: Return (status_code, http.text) tuple to move error handling into
    #    main().
    if http_patch.status_code != 200 \
       and http_patch.status_code != 201:
        error_text = ast.literal_eval(http_patch.text)
        host = data_payload["host_name"]
        print("Status code: {0}\tError: {1}".format(
            http_patch.status_code,
            error_text["full_error"][host]["host_name"]
        ))


def save_work(server_url, ssl_check, auth_pair):
    logger = logging.getLogger(__name__)
    server_target = '/'.join(
        [
            server_url,
            "api",
            "config",
            "change",
        ]
    )
    http_post_save = requests.post(
        server_target,
        data=json.dumps({}),
        verify=ssl_check,
        auth=auth_pair,
        headers={'content-type': 'application/json'},
        params={'format': 'json'}
    )
    print("Saving work.")
    logger.info("Saving work.")
    logger.info('Header: {0}'.format(http_post_save.headers))
    logger.info('Request: {0}'.format(http_post_save.request))
    logger.info('Status code: {0}\tText: {1}'.format(
        http_post_save.status_code,
        http_post_save.text
    ))

    if http_post_save.status_code != 200 \
       and http_post_save.status_code != 201:
        error_text = ast.literal_eval(http_post_save.text)
        print("Status code: {0}\tError: {1}".format(
            http_post_save.status_code,
            error_text["full_error"]["type"]
        ))


def main():
    log_format = ':'.join(
        [
            '%(asctime)s',
            '%(levelname)s',
            '%(filename)s',
            '%(funcName)s',
            '%(lineno)s',
            '%(message)s',
        ]
    )
    logging.basicConfig(
        format=log_format,
        level=logging.INFO,
        filename="switchcase.log"
    )
    logger = logging.getLogger(__name__)

    ssl_check = True
    description = "Switches the case of hosts in OP5 Monitor."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "account",
        help="Account to log into OP5 Monitor."
    )
    parser.add_argument(
        "password",
        help="Account password for OP5 Monitor."
    )
    parser.add_argument(
        "-n",
        "--nop",
        action='store_true',
        help="Dry run, no operations are executed."
    )
    parser.add_argument(
        "-p",
        "--pop",
        action='store_true',
        help="Partial operations, don't save anything."
    )
    parser.add_argument(
        "-d",
        "--dest-url",
        dest='url',
        default="https://localhost",
        help="The URL of the OP5 installation. Default: https://localhost"
    )
    parser.add_argument(
        '--nossl',
        action='store_true',
        help="Supress SSL warning."
    )
    parser.add_argument(
        '-l',
        '--lower',
        action='store_true',
        help="Switch case to lowercase."
    )
    parser.add_argument(
        '-u',
        '--upper',
        action='store_true',
        help="Switch case to uppercase."
    )
    parser.add_argument(
        '-i',
        '--save-interval',
        type=int,
        default=20,
        dest="save_interval",
        help="Sets the interval between saves.",
    )
    parser.add_argument(
        "-f",
        "--listfile",
        help="File containing the hosts."
    )
    args = parser.parse_args()

    # TODO: Figure out if argparse can deal with this.
    if not args.lower and not args.upper:
        logger.error("No cases selected. Please, pick one.")
        print("No cases selected. Please, pick one.")
        return 10
    elif args.lower and args.upper:
        logger.error("Both cases selected. Please, pick one.")
        print("Both cases selected. Please, pick one.")
        return 10
    elif args.lower:
        # We're going to search for server names which are not all lowercase.
        hostname_regex = re.compile('.*[A-Z]+')
    elif args.upper:
        # We're going to search for server names which are not all uppercase.
        hostname_regex = re.compile('.*[a-z]+')

    if args.nossl:
        print("Supressing SSL warnings...")
        ssl_check = False
        requests.packages.urllib3.disable_warnings()

    auth_pair = (args.account, args.password)
    server_target = "/".join(
        [
            args.url,
            'api',
            'config',
        ]
    )
    save_interval = args.save_interval
    save_check = 0

    host_list = get_hosts(server_target, auth_pair, ssl_check)

    for server in host_list:
        if check_hostname(hostname_regex, server["name"]):
            if args.lower:
                hostname_new = server["name"].lower()
            elif args.upper:
                hostname_new = server["name"].upper()
        else:
            continue

        print("Switching {0} to {1}.".format(server["name"], hostname_new))
        logger.info("Switching {0} to {1}.".format(
            server["name"],
            hostname_new)
        )

        data_payload = {"host_name": unicode.encode(hostname_new)}
        logger.info("Data Payload: {0}".format(data_payload))
        logger.info("Server target: {0}".format(server["resource"]))

        if not args.nop:
            update_host(server["resource"], data_payload, auth_pair, ssl_check)

        if save_check < save_interval:
            save_check += 1
        elif args.nop or args.pop:
            print("No op or partial op. Not saving.")
            logger.info("No op or partial op. Not saving.")
        else:
            save_work(args.url, ssl_check, auth_pair)
            save_check = 0

    if args.nop or args.pop:
        print("No op or partial op. Not saving.")
        logger.info("No op or partial op. Not saving.")
    else:
        save_work(args.url, ssl_check, auth_pair)

    return 0


if __name__ == '__main__':
    main()
