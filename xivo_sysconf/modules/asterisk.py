# -*- coding: utf-8 -*-

# Copyright (C) 2011-2013 Avencall
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
from flask.helpers import make_response
from xivo_sysconf.sysconfd_server import app
from xivo.asterisk.voicemail import AsteriskVoicemail

voicemail = AsteriskVoicemail()

@app.route('/delete_voicemail/<context>/<mailbox>', methods=['DELETE'])
def delete_voicemail(context, mailbox):
    res = json.dumps(voicemail.delete(context, mailbox))
    return make_response(res, 200, None, 'application/json')
