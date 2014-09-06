# -*- coding: utf-8 -*-
#
# Copyright (C) 2014 Avencall
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

import argparse
import os
import yaml

from StringIO import StringIO

SysconfDefaultsConf = StringIO("""
[general]
xivo_config_path        = /etc/xivo
templates_path          = /usr/share/xivo-sysconfd/templates
custom_templates_path   = /etc/xivo/sysconfd/custom-templates
backup_path             = /var/backups/xivo-sysconfd
""")

_DAEMONNAME = 'xivo-sysconfd'
_CONF_FILENAME = '{}.yml'.format(_DAEMONNAME)


class ConfigXivosysconfd(object):

    _LOG_FILENAME = '/var/log/{}.log'.format(_DAEMONNAME)
    _PID_FILENAME = '/var/run/{daemon}/{daemon}.pid'.format(daemon=_DAEMONNAME)
    _SOCKET_FILENAME = '/tmp/{}.sock'.format(_DAEMONNAME)

    def __init__(self, adict):
        self._update_config(adict)

    def _update_config(self, adict):
        self.__dict__.update(adict)
        for k, v in adict.items():
            if isinstance(v, dict):
                self.__dict__[k] = ConfigXivosysconfd(v)


def configure():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f",
                        '--foreground',
                        action='store_true',
                        default=False,
                        help="Foreground, don't daemonize")
    parser.add_argument('-d',
                        '--debug',
                        action='store_true',
                        default=False,
                        help="Enable debug messages. Default: %(default)s")
    parser.add_argument("-c",
                        '--config_path',
                        default="/etc/xivo/xivo-sysconfd/",
                        help="Use configuration file <conffile> instead of %default")
    parser.add_argument("-p",
                        '--pidfile',
                        default="/var/run/xivo-sysconfd.pid",
                        help="Use PID file <pidfile> instead of %default")
    parser.add_argument("--la",
                        '--listen_addr',
                        default='127.0.0.1',
                        help="Listen on address <listen_addr> instead of %default")
    parser.add_argument("--lp",
                        '--listen_port',
                        default=8668,
                        help="Listen on port <listen_port> instead of %default")
    return parser.parse_args()

def _get_config_raw(config_path):
    path = os.path.join(config_path, _CONF_FILENAME)
    with open(path) as fobj:
        return yaml.load(fobj)

args_parsed = configure()
config = ConfigXivosysconfd(_get_config_raw(args_parsed.config_path))
config._update_config(vars(args_parsed))
