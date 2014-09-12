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

from xivo.net.dnetintf import DNETIntf
from xivo.net.resolvconf import ResolvConf
from flask import request, jsonify
from xivo_sysconf.sysconfd_server import app

@app.route('/discover_netifaces')
def discover_netifaces():
    net = DNETIntf(app.config['sysconfd'])
    return jsonify(net.discover_netifaces())

@app.route('/netiface/<interface>')
def netiface(interface):
    net = DNETIntf(app.config['sysconfd'])
    return jsonify(net.netiface(interface))

@app.route('/modify_physical_eth_ipv4', methods=['PUT'])
def modify_physical_eth_ipv4():
    net = DNETIntf(app.config['sysconfd'])
    data = request.get_json(True)
    return jsonify(net.modify_physical_eth_ipv4(data))

@app.route('/replace_virtual_eth_ipv4', methods=['PUT'])
def replace_virtual_eth_ipv4():
    net = DNETIntf(app.config['sysconfd'])
    data = request.get_json(True)
    return jsonify(net.replace_virtual_eth_ipv4(data))

@app.route('/modify_eth_ipv4', methods=['PUT'])
def modify_eth_ipv4():
    net = DNETIntf(app.config['sysconfd'])
    data = request.get_json(True)
    return jsonify(net.modify_eth_ipv4(data))

@app.route('/change_state_eth_ipv4', methods=['PUT'])
def change_state_eth_ipv4():
    net = DNETIntf(app.config['sysconfd'])
    data = request.get_json(True)
    return jsonify(net.change_state_eth_ipv4(data))

@app.route('/delete_eth_ipv4/<interface>')
def delete_eth_ipv4(interface):
    net = DNETIntf(app.config['sysconfd'])
    return jsonify(net.delete_eth_ipv4(interface))

@app.route('/network_config')
def network_config():
    net = DNETIntf(app.config['sysconfd'])
    return jsonify(net.network_config())

@app.route('/rename_ethernet_interface', methods=['PUT'])
def rename_ethernet_interface(interface):
    net = DNETIntf(app.config['sysconfd'])
    return jsonify(net.rename_ethernet_interface(interface))

@app.route('/swap_ethernet_interfaces', methods=['PUT'])
def swap_ethernet_interfaces(interface):
    net = DNETIntf(app.config['sysconfd'])
    return jsonify(net.swap_ethernet_interfaces(interface))

@app.route('/routes', methods=['PUT'])
def routes(interface):
    net = DNETIntf(app.config['sysconfd'])
    return jsonify(net.routes(interface))

@app.route('/hosts', methods=['PUT'])
def hosts():
    dns = ResolvConf(app.config['sysconfd'])
    return jsonify(dns.hosts())

@app.route('/resolv_conf', methods=['PUT'])
def resolv_conf():
    dns = ResolvConf(app.config['sysconfd'])
    return jsonify(dns.resolvconf())
