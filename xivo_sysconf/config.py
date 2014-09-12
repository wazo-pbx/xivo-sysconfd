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
import pprint
from xivo.xivo_logging import get_log_level_by_name

_DAEMONNAME = 'xivo-sysconfd'
_CONF_FILENAME = '{}.yml'.format(_DAEMONNAME)

class ConfigSysconfd(object):

    LOG_FILENAME = '/var/log/{}.log'.format(_DAEMONNAME)
    PID_FILENAME = '/var/run/{daemon}/{daemon}.pid'.format(daemon=_DAEMONNAME)
    SOCKET_FILENAME = '/tmp/{}.sock'.format(_DAEMONNAME)

    def __init__(self, d):
        for k in d:
            if isinstance(d[k], dict):
                self.__dict__[k] = ConfigSysconfd(d[k])
            elif isinstance(d[k], (list, tuple)):
                l = []
                for v in d[k]:
                    if isinstance(v, dict):
                        l.append(ConfigSysconfd(v))
                    else:
                        l.append(v)
                self.__dict__[k] = l
            else:
                self.__dict__[k] = d[k]

    def __getitem__(self, name):
        if name in self.__dict__:
            return self.__dict__[name]

    def __iter__(self):
        return iter(self.__dict__.keys())

    def __repr__(self):
        return pprint.pformat(self.__dict__)

    @property
    def debug(self):
        return self.loglevel is 'debug'

def _get_cli_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f",
                        '--foreground',
                        action='store_true',
                        default=False,
                        help="Foreground, don't daemonize")
    parser.add_argument('-l',
                        '--loglevel',
                        help="Emit traces with LOGLEVEL details, must be one of:\n"
                             "critical, error, warning, info, debug  Default: %(default)s")
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
    return parser.parse_args()

def _get_file_config(config_path):
    path = os.path.join(config_path, _CONF_FILENAME)
    with open(path) as fobj:
        return yaml.load(fobj)

def fetch_and_merge_config():
    parsed_cli_args = _get_cli_args()
    raw_file_config = _get_file_config(parsed_cli_args.config_path)
    args_parsed_dict = vars(parsed_cli_args)
    if args_parsed_dict['loglevel'] is None:
        args_parsed_dict['loglevel'] = raw_file_config['loglevel']
    raw_file_config.update(args_parsed_dict)
    config_obj = ConfigSysconfd(raw_file_config)
    config_obj.loglevel = get_log_level_by_name(config_obj.loglevel)

    return config_obj
