# Copyright 2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from .helpers.base import (
    APIIntegrationTest,
    use_asset,
)


@use_asset('base')
class TestDeleteVoicemail(APIIntegrationTest):
    def test_list(self, user_1, user_2):
        presences = self.chatd.user_presences.list()
        assert presences

    def test_get_unknown_uuid(self):
        pass
        # assert_that(
        #     calling(self.chatd.user_presences.get).with_args(str(UNKNOWN_UUID)),
        #     raises(
        #         ChatdError,
        #         has_properties(
        #             status_code=404,
        #             error_id='unknown-user',
        #             resource='users',
        #             details=is_not(none()),
        #             message=is_not(none()),
        #             timestamp=is_not(none()),
        #         ),
        #     ),
        # )
