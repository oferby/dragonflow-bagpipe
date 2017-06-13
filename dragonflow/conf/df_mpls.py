# Copyright (c) 2017 Huawei Tech. Co., Ltd. .
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg

from dragonflow._i18n import _

df_mpls_app_opts = [
    cfg.StrOpt('mpls_bridge', default='br-int',
               help=_('OVS bridge that handles MPLS packets')),
    cfg.IPOpt('ip_address', default='1.1.1.1'),
    cfg.StrOpt('mpls_mac', default='00:00:00:00:00:11'),
    cfg.StrOpt('mpls_port', default='eth1'),
]


def register_opts():
    cfg.CONF.register_opts(df_mpls_app_opts, group='df_mpls')


def list_opts():
    return {'df_mpls': df_mpls_app_opts}
