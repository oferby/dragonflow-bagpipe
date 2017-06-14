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

from jsonmodels import fields

import dragonflow.db.model_framework as mf
import dragonflow.db.field_types as df_fields
from dragonflow.db.models import mixins


@mf.register_model
@mf.construct_nb_db_model
class RemoteLabeledRoute(mf.ModelBase, mixins.BasicEvents):
    table_name = 'rlroutes'

    destination = df_fields.IpNetworkField(required=True)
    nexthop = df_fields.IpAddressField(required=True)
    label = fields.IntField(required=True)
    helper_port = fields.StringField(required=True)


@mf.register_model
@mf.construct_nb_db_model
class LocalLabeledRoute(mf.ModelBase, mixins.BasicEvents):
    table_name = 'llroutes'

    dest_ip = df_fields.IpNetworkField(required=True)
    # dest_mac = df_fields.MacAddressField(required=True)
    port = fields.StringField(required=True)
    # host = df_fields.IpAddressField(required=True)
    label = fields.IntField(required=True)
