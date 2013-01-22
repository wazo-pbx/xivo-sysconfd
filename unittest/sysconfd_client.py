#!/usr/bin/python
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

__version__ = "$Revision$ $Date$"
__author__  = "Guillaume Bour <gbour@proformatique.com>"

import httplib, urllib
import cjson as json

class SysconfdClient():
    def __init__(self):
        self.headers = {
            "Content-type": "application/json",
            "Accept": "text/plain"
        }
        
        self.conn = httplib.HTTPConnection('localhost', 8668)
        
    def request(self, method, uri, params):
        if method == 'POST':
            params = json.encode(params)
        else:
            uri    = "%s?%s" % (uri, urllib.urlencode(params))
            params = None

        self.conn.request(method, uri, params, self.headers)
        response = self.conn.getresponse()
        data     = response.read()
        
        return (response, data)

