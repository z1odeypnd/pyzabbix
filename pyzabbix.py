#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import logging
import re
import socket
import struct

logging.getLogger(__name__).addHandler(logging.NullHandler())


class ZabbixSender(object):
    """part of https://github.com/zabbix/zabbix/tree/master/src/zabbix_sender"""

    def __init__(self, **kwargs):
        self.zabbix_server = '127.0.0.1'
        if 'zabbix_server' in kwargs.keys():
            self.zabbix_server = kwargs["zabbix_server"]
        self.zabbix_port = 10051
        if 'zabbix_port' in kwargs.keys():
            self.zabbix_port = kwargs["zabbix_port"]
        self._host = None
        self._key = None
        self._value = None
        self._connection_timeout = 10
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
        https://www.zabbix.com/documentation/4.2/manual/appendix/protocols/header_datalen <PROTOCOL> - "ZBXD" (4
        bytes). <FLAGS> -the protocol flags, (1 byte). 0x01 - Zabbix communications protocol, 0x02 - compression).
        <DATALEN> - data length (4 bytes). 1 will be formatted as 01/00/00/00 (four bytes, 32 bit number in
        little-endian format). <RESERVED> - reserved for protocol extensions (4 bytes). """
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
        except socket.timeout:
            self._connection.close()
            raise socket.timeout
        except Exception as ex:
            self._connection.close()
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

    def send_metrics(self, **kwargs):
        self._host = kwargs["host"]
        self._key = kwargs["key"]
        self._value = kwargs["value"]
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
    def host(self):
        """Must contains hostname same as zabbix field 'Host name' in Zabbix -> Configuration -> Hosts -> your_host"""
        return self._host

    @property
    def response(self):
        """Contains Zabbix server response"""
        return json.dumps(self._response, indent=4, sort_keys=False, ensure_ascii=False)

    @property
    def rc(self):
        """Contain return code from zabbix response"""
        return self._return_code
