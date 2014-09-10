# -*- coding: utf-8 -*-

# Copyright (C) 2013 Avencall
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

import logging, subprocess
import json

from xivo_sysconf.modules.services import Services

from flask.helpers import make_response
from ..sysconfd_server import app

logger = logging.getLogger('xivo_sysconf.modules.xivoctl')

class XiVOCTL(object):

    def action(service, action):
        if service == 'xivo-service':
            try:
                if act == 'start':
                    Services.action('asterisk', 'stop')
                p = subprocess.Popen(["%s" % service, act],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,
                                     close_fds=True)
                output = p.communicate()[0]
                logger.debug("%s %s : %d", service, act, p.returncode)

                if p.returncode != 0:
                    raise (output)
            except OSError:
                logger.exception("Error while executing %s script", service, act)
                raise ("can't manage xivoctl")
        else:
            logger.error("service not exist: %s", service)

        return output

xivoctl = XiVOCTL()

@app.route('/xivoctl/<service>/<action>')
def xivo_ctl(service, action):
    res_action = xivoctl.action(service, action).rstrip()
    res = json.dumps({"Message": res_action})
    return make_response(res, 200, None, 'application/json')
