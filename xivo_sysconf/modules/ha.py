# -*- coding: utf-8 -*-

# Copyright (C) 2012-2013 Avencall
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
from xivo.sys.ha import _PostgresConfigUpdater, _CronFileInstaller, HAConfigManager


@app.route('/get_ha_config')
def get_ha_config():
    ha_config_manager = HAConfigManager(_PostgresConfigUpdater, _CronFileInstaller())
    return jsonify(ha_config_manager.get_ha_config())

@app.route('/update_ha_config', methods=['POST'])
def update_ha_config():
    ha_config_manager = HAConfigManager(_PostgresConfigUpdater, _CronFileInstaller())
    data = request.get_json(True)
    return jsonify(ha_config_manager.update_ha_config(data))
