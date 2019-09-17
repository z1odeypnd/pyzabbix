Zabbix module for Python
========================

Install
-------

You can install Zabbix modules for Python with pip:

    pip install pyzabbix
Example
--------

ZabbixSender

```python
from pyzabbix import ZabbixSender

# Create ZabbixSender class instance
zabbix_sender = ZabbixSender(zabbix_server='127.0.0.1', zabbix_port=10051)
# Send metric to zabbix trapper
zabbix_sender.send_metrics(host='localhost', key='zabbix_trapper.key', value=1)
# Print request body
print(zabbix_sender.request)
# Print response body
print(zabbix_sender.response)
# Print return code from zabbix sender
print(zabbix_sender.rc)
```
