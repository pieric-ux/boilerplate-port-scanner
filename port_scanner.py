import socket
import re
import ipaddress
from common_ports import ports_and_services


def is_ip(target):
    reg = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    return bool(reg.match(target))


def is_valid_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_valid_hostname(target):
    try:
        socket.gethostbyname(target)
        return True
    except (socket.gaierror, socket.herror):
        return False


def get_open_ports(target, port_range, verbose=False):
    open_ports = []

    if is_ip(target):
        if not is_valid_ip(target) or not is_valid_hostname(target):
            return 'Error: Invalid IP address'
        try:
            hostname, *_ = socket.gethostbyaddr(target)
        except (socket.gaierror, socket.herror):
            hostname = None
        ip_addr = target
    else:
        if not is_valid_hostname(target):
            return 'Error: Invalid hostname'
        hostname = target
        try:
            ip_addr = socket.gethostbyname(target)
        except (socket.gaierror, socket.herror):
            ip_addr = None

    for port in range(port_range[0], port_range[1] + 1):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        if sock.connect_ex((ip_addr, port)) == 0:
            open_ports.append(port)

        sock.close()

    if verbose:
      heading = f'Open ports for'
      if not hostname:
        heading += f' {ip_addr}'
      else:
        heading += f' {hostname} ({ip_addr})'
      header = 'PORT'.ljust(9,' ') + 'SERVICE'
      body = '\n'.join([f'{port}'.ljust(9,' ') + ports_and_services[port] for port in open_ports])

      return f'{heading}\n{header}\n{body}'
    else:
      return open_ports