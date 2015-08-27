# Copyright (c) 2015 OpenStack Foundation.
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import etcd
import netaddr

from oslo_log import log
from oslo_serialization import jsonutils

from neutron.i18n import _LW

from dragonflow.db import api_nb

LOG = log.getLogger(__name__)


class EtcdNbApi(api_nb.NbApi):

    def __init__(self):
        super(EtcdNbApi, self).__init__()
        self.client = None
        self.current_key = 0
        self.controller = None

    def initialize(self, db_ip='127.0.0.1', db_port=4001):
        self.client = etcd.Client(host=db_ip, port=db_port)

    def support_publish_subscribe(self):
        return True

    def wait_for_db_changes(self, controller):
        self.controller = controller
        while True:
            try:
                self._poll_for_data_changes()
            except Exception as e:
                if "Read timed out" not in e.message and (
                            "ofport is 0" not in e.message):
                    LOG.warn(_LW("suppressing configuration exception"))
                    LOG.warn(e)

    # TODO(gsagie) implement this to send the updates to a controller local
    # queue which will process these updates
    def _poll_for_data_changes(self):
        entry = self.client.read('/', wait=True, recursive=True,
                                 waitIndex=self.current_key)

        self.controller.vswitch_api.sync()
        if 'lport' in entry.key:
            if entry.action == 'set' or entry.action == 'create':
                lport = EtcdLogicalPort(entry.value)
                self.controller.logical_port_updated(lport)
            else:
                lport_id = entry.key.split('/')[2]
                self.controller.logical_port_deleted(lport_id)
        if 'lrouter' in entry.key:
            if entry.action == 'set' or entry.action == 'create':
                lrouter = EtcdLogicalRouter(entry.value)
                self.controller.router_updated(lrouter)
            else:
                lrouter_id = entry.key.split('/')[2]
                self.controller.router_deleted(lrouter_id)
        if 'chassis' in entry.key:
            if entry.action == 'set' or entry.action == 'create':
                chassis = EtcdChassis(entry.value)
                self.controller.chassis_created(chassis)
            else:
                chassis_id = entry.key.split('/')[2]
                self.controller.chassis_deleted(chassis_id)
        if 'lswitch' in entry.key:
            if entry.action == 'set' or entry.action == 'create':
                lswitch = EtcdLogicalSwitch(entry.value)
                self.controller.logical_switch_updated(lswitch)
            else:
                lswitch_id = entry.key.split('/')[2]
                self.controller.logical_switch_deleted(lswitch_id)

        self.current_key = entry.modifiedIndex + 1

    def sync(self):
        pass

    def get_chassis(self, name):
        try:
            chassis_value = self.client.read('/chassis/' + name).value
            return EtcdChassis(chassis_value)
        except Exception:
            return None

    def get_all_chassis(self):
        res = []
        directory = self.client.get("/chassis")
        for result in directory.children:
            res.append(EtcdChassis(result.value))
        return res

    def add_chassis(self, name, ip, tunnel_type):
        chassis_value = name + ',' + ip + ',' + tunnel_type
        self.client.write('/chassis/' + name, chassis_value)

    def get_lswitch(self, name):
        try:
            lswitch_value = self.client.read('/lswitch/' + name).value
            return EtcdLogicalSwitch(lswitch_value)
        except Exception:
            return None

    def add_subnet(self, id, lswitch_name, **columns):
        lswitch_json = self.client.read('/lswitch/' + lswitch_name).value
        lswitch = jsonutils.loads(lswitch_json)

        subnet = {}
        subnet['id'] = id
        subnet['lswitch'] = lswitch_name
        for col, val in columns.items():
            subnet[col] = val

        subnets = lswitch.get('subnets', [])
        subnets.append(subnet)
        lswitch['subnets'] = subnets
        lswitch_json = jsonutils.dumps(lswitch)
        self.client.write('/lswitch/' + lswitch_name, lswitch_json)

    def delete_subnet(self, id, lswitch_name):
        lswitch_json = self.client.read('/lswitch/' + lswitch_name).value
        lswitch = jsonutils.loads(lswitch_json)

        new_ports = []
        for subnet in lswitch.get('subnets', []):
            if subnet['id'] != id:
                new_ports.append(subnet)

        lswitch['subnets'] = new_ports
        lswitch_json = jsonutils.dumps(lswitch)
        self.client.write('/lswitch/' + lswitch_name, lswitch_json)

    def get_logical_port(self, port_id):
        try:
            port_value = self.client.read("/lport/" + port_id).value
            return EtcdLogicalPort(port_value)
        except Exception:
            return None

    def get_all_logical_ports(self):
        res = []
        directory = self.client.get("/lport")
        for lport_entry in directory.children:
            lport = EtcdLogicalPort(lport_entry.value)
            if lport.get_chassis() is None:
                continue
            res.append(lport)
        return res

    def create_lswitch(self, name, **columns):
        lswitch = {}
        lswitch['name'] = name
        for col, val in columns.items():
            lswitch[col] = val
        lswitch_json = jsonutils.dumps(lswitch)
        self.client.write('/lswitch/' + name, lswitch_json)

    def update_lswitch(self, name, **columns):
        lswitch_json = self.client.read('/lswitch/' + name).value
        lswitch = jsonutils.loads(lswitch_json)
        for col, val in columns.items():
            lswitch[col] = val
        lswitch_json = jsonutils.dumps(lswitch)
        self.client.write('/lswitch/' + name, lswitch_json)

    def delete_lswitch(self, name):
        self.client.delete('/lswitch/' + name)

    def create_lport(self, name, lswitch_name, **columns):
        lport = {}
        lport['name'] = name
        lport['lswitch'] = lswitch_name
        for col, val in columns.items():
            lport[col] = val
        lport_json = jsonutils.dumps(lport)
        self.client.write('/lport/' + name, lport_json)

    def update_lport(self, name, **columns):
        lport_json = self.client.read('/lport/' + name).value
        lport = jsonutils.loads(lport_json)
        for col, val in columns.items():
            lport[col] = val
        lport_json = jsonutils.dumps(lport)
        self.client.write('/lport/' + name, lport_json)

    def delete_lport(self, name):
        self.client.delete('/lport/' + name)

    def create_lrouter(self, name, **columns):
        lrouter = {}
        lrouter['name'] = name
        for col, val in columns.items():
            lrouter[col] = val
        lrouter_json = jsonutils.dumps(lrouter)
        self.client.write('/lrouter/' + name, lrouter_json)

    def delete_lrouter(self, name):
        self.client.delete('/lrouter/' + name)

    def add_lrouter_port(self, name, lrouter_name, lswitch, **columns):
        lrouter_json = self.client.read('/lrouter/' + lrouter_name).value
        lrouter = jsonutils.loads(lrouter_json)

        lrouter_port = {}
        lrouter_port['name'] = name
        lrouter_port['lrouter'] = lrouter_name
        lrouter_port['lswitch'] = lswitch
        for col, val in columns.items():
            lrouter_port[col] = val

        router_ports = lrouter.get('ports', [])
        router_ports.append(lrouter_port)
        lrouter['ports'] = router_ports
        lrouter_json = jsonutils.dumps(lrouter)
        self.client.write('/lrouter/' + lrouter_name, lrouter_json)

    def delete_lrouter_port(self, lrouter_name, lswitch):
        lrouter_json = self.client.read('/lrouter/' + lrouter_name).value
        lrouter = jsonutils.loads(lrouter_json)

        new_ports = []
        for port in lrouter.get('ports', []):
            if port['lswitch'] != lswitch:
                new_ports.append(port)

        lrouter['ports'] = new_ports
        lrouter_json = jsonutils.dumps(lrouter)
        self.client.write('/lrouter/' + lrouter_name, lrouter_json)

    def get_routers(self):
        res = []
        directory = self.client.get("/lrouter")
        for result in directory.children:
            res.append(EtcdLogicalRouter(result.value))
        return res

    def get_all_logical_switches(self):
        res = []
        directory = self.client.get("/lswitch")
        for result in directory.children:
            res.append(EtcdLogicalSwitch(result.value))
        return res


class EtcdChassis(api_nb.Chassis):

    def __init__(self, value):
        # Entry <chassis_name, chassis_ip, chassis_tunnel_type>
        self.values = value.split(',')

    def get_name(self):
        return self.values[0]

    def get_ip(self):
        return self.values[1]

    def get_encap_type(self):
        return self.values[2]

    def __str__(self):
        return self.values.__str__()


class EtcdLogicalSwitch(api_nb.LogicalSwitch):

    def __init__(self, value):
        self.lswitch = jsonutils.loads(value)

    def get_id(self):
        return self.lswitch['name']

    def get_subnets(self):
        res = []
        for subnet in self.lswitch['subnets']:
            res.append(EtcdSubnet(subnet))
        return res

    def __str__(self):
        return self.lswitch.__str__()


class EtcdSubnet(api_nb.Subnet):

    def __init__(self, value):
        self.subnet = value

    def get_dhcp_enabled(self):
        return self.subnet['enable_dhcp']

    def get_dhcp_server_address(self):
        return self.subnet['dhcp_ip']

    def get_cidr(self):
        return self.subnet['cidr']

    def get_gateway_ip(self):
        return self.subnet['gateway_ip']


class EtcdLogicalPort(api_nb.LogicalPort):

    def __init__(self, value):
        self.external_dict = {}
        self.lport = jsonutils.loads(value)

    def get_id(self):
        return self.lport.get('name')

    def get_ip(self):
        return self.lport['ips'][0]

    def get_mac(self):
        return self.lport['macs'][0]

    def get_chassis(self):
        return self.lport.get('chassis')

    def get_lswitch_id(self):
        return self.lport.get('lswitch')

    def get_tunnel_key(self):
        return int(self.lport['tunnel_key'])

    def set_external_value(self, key, value):
        self.external_dict[key] = value

    def get_external_value(self, key):
        return self.external_dict.get(key)

    def get_device_owner(self):
        return self.lport.get('device_owner')

    def __str__(self):
        return self.lport.__str__() + self.external_dict.__str__()


class EtcdLogicalRouter(api_nb.LogicalRouter):

    def __init__(self, value):
        self.lrouter = jsonutils.loads(value)

    def get_name(self):
        return self.lrouter.get('name')

    def get_ports(self):
        res = []
        for port in self.lrouter.get('ports'):
            res.append(EtcdLogicalRouterPort(port))
        return res

    def __str__(self):
        return self.lrouter.__str__()


class EtcdLogicalRouterPort(api_nb.LogicalRouterPort):

    def __init__(self, value):
        self.router_port = value
        self.cidr = netaddr.IPNetwork(self.router_port['network'])

    def get_name(self):
        return self.router_port.get('name')

    def get_ip(self):
        return str(self.cidr.ip)

    def get_cidr_network(self):
        return str(self.cidr.network)

    def get_cidr_netmask(self):
        return str(self.cidr.netmask)

    def get_mac(self):
        return self.router_port.get('mac')

    def get_lswitch_id(self):
        return self.router_port['lswitch']

    def get_network(self):
        return self.router_port['network']

    def get_tunnel_key(self):
        return self.router_port['tunnel_key']

    def __str__(self):
        return self.router_port.__str__()