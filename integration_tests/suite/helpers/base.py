# Copyright 2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest
import os
import unittest

from xivo_test_helpers.asset_launching_test_case import (
    AssetLaunchingTestCase,
    NoSuchService,
)
from xivo_test_helpers.bus import BusClient

from .sysconfd import SysconfdClient

use_asset = pytest.mark.usefixtures


class ClientCreateException(Exception):
    def __init__(self, client_name):
        super().__init__(f'Could not create client {client_name}')


class WrongClient:
    def __init__(self, client_name):
        self.client_name = client_name

    def __getattr__(self, member):
        raise ClientCreateException(self.client_name)


class APIAssetLaunchingTestCase(AssetLaunchingTestCase):
    asset = 'base'
    service = 'sysconfd'
    assets_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..', '..', 'assets')
    )

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.sysconfd = cls.make_sysconfd()

    @classmethod
    def make_sysconfd(cls):
        try:
            port = cls.service_port(8668, 'sysconfd')
        except NoSuchService:
            return WrongClient('sysconfd')
        return SysconfdClient('localhost', port=port)

    @classmethod
    def make_bus(cls):
        try:
            port = cls.service_port(5672, 'rabbitmq')
        except NoSuchService:
            return WrongClient('rabbitmq')
        return BusClient.from_connection_fields(host='localhost', port=port)


class APIIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reset_clients()

    @classmethod
    def reset_clients(cls):
        cls.sysconfd = APIAssetLaunchingTestCase.make_sysconfd()
        cls.bus = APIAssetLaunchingTestCase.make_bus()
