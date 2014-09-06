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

import logging
import os

from gevent.wsgi import WSGIServer

from xivo.daemonize import pidfile_context
from xivo.xivo_logging import setup_logging
from xivo_sysconf.config import config
from xivo_sysconf import sysconfd_server

logger = logging.getLogger(__name__)

def main():
    setup_logging(config._LOG_FILENAME, config.foreground, config.debug)

    with pidfile_context(config._PID_FILENAME, config.foreground):
        _run()

def _run():
    logger.debug('WSGIServer starting with uid %s', os.getuid())
    http_server = WSGIServer((config.general.listen, config.general.port), sysconfd_server.app)
    http_server.serve_forever()

if __name__ == '__main__':
    main()
