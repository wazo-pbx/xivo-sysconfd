# -*- coding: utf-8 -*-

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

import signal
import logging
import os

from flup.server.fcgi import WSGIServer

from xivo.daemonize import pidfile_context
from xivo.xivo_logging import setup_logging
from xivo_sysconf.config import config
from xivo_sysconf import sysconfd_server
#from xivo_sysconf.modules import *

logger = logging.getLogger(__name__)

def main():
    setup_logging(config._LOG_FILENAME, config.foreground, config.debug)
    if config.user:
        change_user(config.user)

    with pidfile_context(config._PID_FILENAME, config.foreground):
        _run()


def _run():
    logger.debug('WSGIServer starting with uid %s', os.getuid())
    WSGIServer(sysconfd_server.app,
               bindAddress=config._SOCKET_FILENAME,
               multithreaded=True,
               multiprocess=False,
               debug=config.debug).run()


def _init_signal():
    signal.signal(signal.SIGTERM, _handle_sigterm)


def _handle_sigterm(signum, frame):
    raise SystemExit()


if __name__ == '__main__':
    main()
