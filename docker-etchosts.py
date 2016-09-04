#!/usr/bin/env python
"""add/remove containers from host-file using
   docker /events HTTP streaming API"""

from contextlib import closing
from socket import socket, AF_UNIX
from sys import stdout, version_info, platform
import json

if version_info[:2] < (3, 0):
    from httplib import OK as HTTP_OK
    from urlparse import urlparse
else:
    from http.client import OK as HTTP_OK
    from urllib.parse import urlparse

__version__ = '0.0.1'
buffer_size = 1024
default_sock_url = 'ipc:///var/run/docker.sock'
hostsfile = 'hosts'


class DockermonError(Exception):
    pass


def read_http_header(sock):
    """Read HTTP header from socket, return header and rest of data.
    :param sock: socket to send request to
    """
    buf = []
    hdr_end = '\r\n\r\n'

    while True:
        buf.append(sock.recv(buffer_size).decode('utf-8'))
        data = ''.join(buf)
        i = data.find(hdr_end)
        if i == -1:
            continue
        return data[:i], data[i + len(hdr_end):]


def header_status(header):
    """Parse HTTP status line, return status (int) and reason.
    :param header: header data
    """
    status_line = header[:header.find('\r')]
    # 'HTTP/1.1 200 OK' -> (200, 'OK')
    fields = status_line.split(None, 2)
    return int(fields[1]), fields[2]


def connect(url):
    """Connect to UNIX or TCP socket.

        :param url: can be either tcp://<host>:port or ipc://<path>
    """
    url = urlparse(url)
    if url.scheme == 'tcp':
        sock = socket()
        netloc = tuple(url.netloc.rsplit(':', 1))
        hostname = socket.gethostname()
    elif url.scheme == 'ipc':
        sock = socket(AF_UNIX)
        netloc = url.path
        hostname = 'localhost'
    else:
        raise ValueError('unknown socket type: %s' % url.scheme)

    sock.connect(netloc)
    return sock, hostname


def lookup_ip(container_id, url=default_sock_url):
    """Fetch a running containers IP from the docker API.

    :param container_id: id or name to look up IP for
    :param url: docker API. can be either tcp://<host>:port or ipc://<path>
    :return: IPv4
    :rtype: str
    """
    sock, hostname = connect(url)
    request = 'GET /containers/{}/json HTTP/1.1\nHost: {}\n\n'.format(
        container_id,
        hostname,
    )
    request = request.encode('utf-8')

    with closing(sock):
        sock.sendall(request)
        header, payload = read_http_header(sock)
        status, reason = header_status(header)
        if status != HTTP_OK:
            raise DockermonError('bad HTTP status: %s %s' % (status, reason))
        payload = payload[payload.find('\r\n') + 2:]
        buf = [payload]
        while True:
            chunk = sock.recv(buffer_size)
            buf.append(chunk.decode('utf-8'))
            data = ''.join(buf)
            if data.endswith('\n\r\n0\r\n\r\n'):
                break
        data = json.loads(data[:-6])

    return data.get('NetworkSettings', {}).get('IPAddress')


def process_all_running_containers(url=default_sock_url):
    """Add/Update all running containers IPs to hosts-file.
    Used at script startup.

    :param url: docker API. can be either tcp://<host>:port or ipc://<path>
    """
    sock, hostname = connect(url)
    request = 'GET /containers/json HTTP/1.1\nHost: {}\n\n'.format(hostname)
    request = request.encode('utf-8')

    with closing(sock):
        sock.sendall(request)
        header, payload = read_http_header(sock)
        status, reason = header_status(header)
        if status != HTTP_OK:
            raise DockermonError('bad HTTP status: %s %s' % (status, reason))
        payload = payload[payload.find('\r\n') + 2:]
        buf = [payload]
        while True:
            chunk = sock.recv(buffer_size)
            buf.append(chunk.decode('utf-8'))
            data = ''.join(buf)
            if data.endswith('\n\r\n0\r\n\r\n'):
                break
        data = json.loads(data[:-6])

    for container in data:
        _update_hosts_file(
            container.get('Names', [])[0].strip('/'),
            lookup_ip(container.get("Id"))
        )


def watch(callback, url=default_sock_url):
    """Watch docker events. Will call callback with each new event (dict).

        :param callback: callback function for received events.
        :param url: docker API. can be either tcp://<host>:port or ipc://<path>
    """
    sock, hostname = connect(url)
    request = 'GET /events HTTP/1.1\nHost: {}\n\n'.format(hostname)
    request = request.encode('utf-8')

    with closing(sock):
        sock.sendall(request)
        header, payload = read_http_header(sock)
        status, reason = header_status(header)
        if status != HTTP_OK:
            raise DockermonError('bad HTTP status: %s %s' % (status, reason))

        # Messages are \r\n<size in hex><JSON payload>\r\n
        buf = [payload]
        while True:
            chunk = sock.recv(buffer_size)
            if not chunk:
                raise EOFError('socket closed')
            buf.append(chunk.decode('utf-8'))
            data = ''.join(buf)
            i = data.find('\r\n')
            if i == -1:
                continue

            size = int(data[:i], 16)
            start = i + 2  # Skip initial \r\n

            if len(data) < start + size + 2:
                continue
            payload = data[start:start + size]
            callback(json.loads(payload))
            buf = [data[start + size + 2:]]  # Skip \r\n suffix


def process_callback(msg):
    """Process events and route to applicable functions.
    :param msg: docker event as received from API.
    """
    if ('Type' in msg and msg['Type'] == 'container' and
            msg['Action'] == 'start'):
        _container_start(msg)
    if ('Type' in msg and msg['Type'] == 'container' and
            msg['Action'] == 'destroy'):
        _container_destroy(msg)
    # also print all events to stdout for logspout to catch
    json.dump(msg, stdout)
    stdout.write('\n')
    stdout.flush()


def _container_start(msg):
    """

    :param msg:
    """
    container_name = msg.get('Actor', {}).get('Attributes', {}).get("name")
    container_id = msg.get('Actor', {}).get('ID')
    container_ip = lookup_ip(container_id)
    _update_hosts_file(container_name, container_ip)


def _container_destroy(msg):
    """

    :param msg:
    """
    container_name = msg.get('Actor', {}).get('Attributes', {}).get("name")
    _update_hosts_file(container_name)


def _update_hosts_file(hostname, ip_address=None):
    """
    The update function takes the ip address and hostname passed into the
    function and adds it to the host file.
    :param ip_address:
    :param hostname:
    """

    if not ip_address:
        with open(hostsfile, "r+") as f:
            lines = f.readlines()
            f.seek(0)
            f.writelines([line for line in lines if hostname not in line])
            f.truncate()
        return

    with open(hostsfile, "r") as f:
        lines = f.readlines()
        if any(hostname in s for s in lines):
            altered_lines = ["{} {}\n".format(ip_address, hostname)
                             if hostname in line else line for line in lines]
        else:
            altered_lines = list(lines) + ["{} {}\n".format(
                ip_address,
                hostname,
            )]
    with open(hostsfile, "w") as f:
        f.writelines(altered_lines)


if __name__ == '__main__':
    global hostsfile
    from argparse import ArgumentParser

    parser = ArgumentParser(description=__doc__)
    parser.add_argument(
        '--socket-url', default=default_sock_url,
        help='socket url (ipc:///path/to/sock or tcp:///host:port)'
    )
    parser.add_argument(
        '--skip-running', help='do not process already running containers',
        action='store_true', default=False
    )
    parser.add_argument(
        '--hosts-file', help='hosts file to add/update to', default="hosts"
    )
    parser.add_argument(
        '--version', help='print version and exit',
        action='store_true', default=False
    )
    args = parser.parse_args()

    if args.version:
        print('docker-etchosts %s' % __version__)
        raise SystemExit

    if not args.skip_running:
        process_all_running_containers(args.socket_url)

    hostsfile = args.hosts_file

    try:
        watch(process_callback, args.socket_url)
    except (KeyboardInterrupt, EOFError):
        pass
