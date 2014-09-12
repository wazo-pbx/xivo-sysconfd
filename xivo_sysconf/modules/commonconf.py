# -*- coding: utf-8 -*-

# Copyright (C) 2010-2013 Avencall
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

from flask import request, jsonify
from xivo_sysconf.sysconfd_server import app
from xivo.sys.commonconf import CommonConf

@app.route('/commonconf_apply')
def commonconf_apply():
    commonconf = CommonConf(app.config['sysconfd'])
    return jsonify(commonconf.apply())

@app.route('/commonconf_generate', methods=['POST'])
def commonconf_generate():
    commonconf = CommonConf(app.config['sysconfd'])
    data = request.get_json(True)
    return jsonify(commonconf.generate(data))
