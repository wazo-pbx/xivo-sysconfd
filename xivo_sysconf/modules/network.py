# -*- coding: utf-8 -*-

# Copyright (C) 2008-2013 Avencall
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import json
from xivo_sysconf.config import config
from xivo_sysconf.network.dnetintf import DNETIntf

from flask.helpers import make_response
from flask import request
from ..sysconfd_server import app, VERSION

net = DNETIntf()

@app.route('/discover_netifaces')
def discover_netifaces():
    res = json.dumps(net.discover_netifaces())
    return make_response(res, 200, None, 'application/json')

@app.route('/netiface/<interface>')
def netiface(interface):
    res = json.dumps(net.netiface(interface))
    return make_response(res, 200, None, 'application/json')

@app.route('/modify_physical_eth_ipv4', methods=['PUT'])
def modify_physical_eth_ipv4():
    data = json.loads(request.data)
    res = json.dumps(net.modify_physical_eth_ipv4(data))
    return make_response(res, 200, None, 'application/json')

@app.route('/replace_virtual_eth_ipv4', methods=['PUT'])
def replace_virtual_eth_ipv4():
    data = json.loads(request.data)
    res = json.dumps(net.replace_virtual_eth_ipv4(data))
    return make_response(res, 200, None, 'application/json')

@app.route('/modify_eth_ipv4', methods=['PUT'])
def modify_eth_ipv4():
    data = json.loads(request.data)
    res = json.dumps(net.modify_eth_ipv4(data))
    return make_response(res, 200, None, 'application/json')

@app.route('/change_state_eth_ipv4', methods=['PUT'])
def change_state_eth_ipv4():
    data = json.loads(request.data)
    res = json.dumps(net.change_state_eth_ipv4(data))
    return make_response(res, 200, None, 'application/json')

@app.route('/delete_eth_ipv4/<interface>')
def delete_eth_ipv4(interface):
    res = json.dumps(net.delete_eth_ipv4(interface))
    return make_response(res, 200, None, 'application/json')

@app.route('/network_config')
def network_config():
    res = json.dumps(net.network_config())
    return make_response(res, 200, None, 'application/json')

@app.route('/rename_ethernet_interface', methods=['PUT'])
def rename_ethernet_interface(interface):
    res = json.dumps(net.rename_ethernet_interface(interface))
    return make_response(res, 200, None, 'application/json')

@app.route('/swap_ethernet_interfaces', methods=['PUT'])
def swap_ethernet_interfaces(interface):
    res = json.dumps(net.swap_ethernet_interfaces(interface))
    return make_response(res, 200, None, 'application/json')

@app.route('/routes', methods=['PUT'])
def routes(interface):
    res = json.dumps(net.routes(interface))
    return make_response(res, 200, None, 'application/json')
