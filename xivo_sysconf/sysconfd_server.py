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

import json
import logging
import requests

from flask import Flask, request
from flask.helpers import make_response

logger = logging.getLogger(__name__)
app = Flask(__name__)
session = requests.Session()

VERSION = 0.1

@app.route('/checkup'.format(version=VERSION))
def checkup():
    res = json.dumps({'Message': 'Not Supported'})
    return make_response(res, 501, None, 'application/json')
