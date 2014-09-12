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

from flask import request, jsonify
from xivo.ssl.openssl import OpenSSL
from xivo_sysconf.sysconfd_server import app


@app.route('/openssl_listcertificates')
def listcertificates():
    openssl = OpenSSL(app.config['sysconfd'])
    return jsonify(openssl.listCertificates())

@app.route('/openssl_certificateinfos/<certificate>')
def getcertificatesinfos(certificate):
    openssl = OpenSSL(app.config['sysconfd'])
    return jsonify(openssl.getCertificateInfos(certificate))

@app.route('/openssl_exportpubkey/<certificate>')
def exportpubkey(certificate):
    openssl = OpenSSL(app.config['sysconfd'])
    return jsonify(openssl.getPubKey(certificate))

@app.route('/openssl_export/<certificate>')
def export_certificate(certificate):
    openssl = OpenSSL(app.config['sysconfd'])
    return jsonify(openssl.export(certificate))

@app.route('/openssl_import', methods=['POST'])
def import_certificate():
    openssl = OpenSSL(app.config['sysconfd'])
    return jsonify(openssl._import())

@app.route('/openssl_createcacertificate', methods=['POST'])
def createcacertificate():
    openssl = OpenSSL(app.config['sysconfd'])
    data = request.get_json(True)
    return jsonify(openssl.createSSLCACertificate(data))

@app.route('/openssl_createcertificate', methods=['POST'])
def createcertificate():
    openssl = OpenSSL(app.config['sysconfd'])
    data = request.get_json(True)
    return jsonify(openssl.createSSLCertificate(data))

@app.route('/openssl_deletecacertificate', methods=['DELETE'])
def deletecacertificate():
    openssl = OpenSSL(app.config['sysconfd'])
    return jsonify(openssl.deleteCertificate())
