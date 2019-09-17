#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import logging
import re
import socket
import struct

logging.getLogger(__name__).addHandler(logging.NullHandler())

"""
    Author: Andrey Shokhin (ashohin@neoflex.ru)
    Common path: /etc/zabbix/scripts/pyzabbix/pyzabbix.py
"""


class ZabbixSender(object):
    """part of https://github.com/zabbix/zabbix/tree/master/src/zabbix_sender"""

    def __init__(self, zabbix_server='127.0.0.1', zabbix_port=10051, connection_timeout=10):
        self.zabbix_server = zabbix_server
        self.zabbix_port = zabbix_port
        self._host = None
        self._key = None
        self._value = None
        self._connection_timeout = connection_timeout
        self._response = None
        self._connection = None
        self._metrics_message = []
        self._request_body = None
        self._metrics_packet = None
        self._return_code = 0

    def _create_request_body(self):
        """Request/response body described in oficial Zabbix documentation
        https://www.zabbix.com/documentation/current/manual/appendix/items/trapper"""
        logging.debug("Create request packet body...")
        self._value = json.dumps(self._value, indent=4, sort_keys=False, ensure_ascii=False)
        self._value = str(self._value)
        self._request_body = {
            'request': 'sender data',
            'data': [
                {
                    'host': self._host,
                    'key': self._key,
                    'value': self._value,
                }
            ]
        }
        self._request_body = str(json.dumps(self._request_body, ensure_ascii=False))
        logging.debug("Request packet body: '{}'".format(self._request_body))

    def _make_request(self):
        """Request/response package header and data length described in oficial Zabbix documentation
        https://www.zabbix.com/documentation/current/manual/appendix/protocols/header_datalen
        <PROTOCOL> - "ZBXD" (4 bytes).
        <FLAGS> - the protocol flags, (1 byte). 0x01 - Zabbix communications protocol, 0x02 - compression).
        <DATALEN> - data length (4 bytes). 1 will be formatted as 01/00/00/00 (four bytes, 32 bit number in
            little-endian format).
        <RESERVED> - reserved for protocol extensions (4 bytes). """
        logging.debug("Create request packet...")
        zbx_protocol = "ZBXD"
        zbx_flags = "\1"
        zbx_header = zbx_protocol + zbx_flags
        # Convert header to bytes (5 bytes)
        zbx_header = zbx_header.encode("utf-8")
        # Convert body to bytes
        self._request_body = self._request_body.encode("utf-8")
        # Packet length '<Q' - means 'little-endian, unsigned long long' (8 bytes)
        zbx_datalen = struct.pack('<Q', len(self._request_body))
        self._metrics_packet = zbx_header + zbx_datalen + self._request_body
        logging.debug("Request packet: '{}'".format(self._metrics_packet))
        try:
            logging.debug("Open connection to server: '{}:{}'".format(self.zabbix_server, self.zabbix_port))
            self._connection.connect((self.zabbix_server, self.zabbix_port))
            logging.debug("Send request packet to server: '{}:{}'".format(self.zabbix_server, self.zabbix_port))
            self._connection.sendall(self._metrics_packet)
        except socket.timeout as sotm:
            self._connection.close()
            logging.debug("Connection timeout to host {}:{}! "
                             "Timeout {} sec. Error: '{}'.".format(self.zabbix_server, self.zabbix_port,
                                                                   self._connection_timeout, sotm))
            raise sotm
        except OSError as ose:
            self._connection.close()
            logging.debug("Connection failed to host {}:{} with error '{}'!".format(self.zabbix_server,
                                                                                       self.zabbix_port, ose))
            raise ose
        except Exception as ex:
            self._connection.close()
            logging.debug("Connection failed to host {}:{} with exception '{}'!".format(self.zabbix_server,
                                                                                           self.zabbix_port, ex))
            raise ex

    def _parse_response(self):
        info_regex = re.compile(r'[Pp]rocessed:? (\d*);? [Ff]ailed:? (\d*);? [Tt]otal:? (\d*);? [Ss]econds spent:? ('
                                r'\d*\.\d*)')
        regex_result = info_regex.search(self._response["info"])
        response_info = {
            'processed': int(regex_result.group(1)),
            'failed': int(regex_result.group(2)),
            'total': int(regex_result.group(3)),
            'seconds spent': float(regex_result.group(4))
        }
        self._response.update({'info': response_info})

    def _get_response(self):
        logging.debug("Get response from server: '{}:{}'".format(self.zabbix_server, self.zabbix_port))
        response_header = b''
        zbx_header_len = 13
        while len(response_header) < zbx_header_len:
            chunk = self._connection.recv(zbx_header_len - len(response_header))
            if not chunk:
                break
            response_header += chunk
        response_len = struct.unpack('<Q', response_header[5:])[0]
        response_body = self._connection.recv(response_len)
        self._response = json.loads(response_body.decode("utf-8"))
        logging.debug("Got server response: '{}'".format(self._response))
        self._parse_response()
        if self._response["response"] != "success" or self._response["info"]["failed"] != 0:
            self._return_code += 1

    def send_metrics(self, host=None, key=None, value=None):
        self._host = host
        self._key = key
        self._value = value
        logging.debug("Create metrics message...")
        self._create_request_body()
        logging.debug("Create new connection.")
        self._connection = socket.socket()
        self._connection.settimeout(self._connection_timeout)
        self._make_request()
        self._get_response()
        try:
            logging.debug("Close connection.")
            self._connection.close()
        except:
            pass

    @property
    def request(self):
        """Return request body in json format"""
        try:
            request_body = json.loads(self._request_body.decode("utf-8"))
        except AttributeError:
            request_body = None
        request_body_json = json.dumps(request_body, indent=4, sort_keys=False, ensure_ascii=False)
        return request_body_json

    @property
    def response(self):
        """Contains Zabbix server response"""
        return json.dumps(self._response, indent=4, sort_keys=False, ensure_ascii=False)

    @property
    def rc(self):
        """Contain return code from zabbix response"""
        return self._return_code
