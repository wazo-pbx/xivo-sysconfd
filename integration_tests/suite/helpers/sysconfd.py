# Copyright 2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import requests


class SysconfdClient:
    def __init__(self, host, port):
        self._host = host
        self._port = port

    def url(self, *parts):
        return 'http://{host}:{port}/{path}'.format(
            host=self._host, port=self._port, path='/'.join(parts)
        )

    def delete_voicemail(self, number, context):
        url = self.url('delete_voicemail')
        params = {'mailbox': number, 'context': context}
        requests.get(url, params=params)
