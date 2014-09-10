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

import logging
import json

from flask.helpers import make_response
from ..sysconfd_server import app
from xivo_sysconf.ssl.openssl import OpenSSL

logger = logging.getLogger('xivo_sysconf.modules.ssl')
openssl = OpenSSL()

@app.route('/openssl_listcertificates')
def listcertificates():
    res = json.dumps(openssl.listCertificates)
    return make_response(res, 200, None, 'application/json')

@app.route('/openssl_certificateinfos')
def getcertificatesinfos():
    res = json.dumps(openssl.getCertificatesInfos)
    return make_response(res, 200, None, 'application/json')

@app.route('/openssl_exportpubkey')
def exportpubkey():
    res = json.dumps(openssl.getPubKey)
    return make_response(res, 200, None, 'application/json')

@app.route('/openssl_export')
def export_certificate():
    res = json.dumps(openssl.export)
    return make_response(res, 200, None, 'application/json')

@app.route('/openssl_import')
def import_certificate():
    res = json.dumps(openssl._import)
    return make_response(res, 200, None, 'application/json')

@app.route('/openssl_createcacertificate', methods=['POST'])
def createcacertificate():
    res = json.dumps(openssl.createSSLCACertificate)
    return make_response(res, 200, None, 'application/json')

@app.route('/openssl_deletecacertificate', methods=['DELETE'])
def deletecacertificate():
    res = json.dumps(openssl.deleteCertificate)
    return make_response(res, 200, None, 'application/json')
