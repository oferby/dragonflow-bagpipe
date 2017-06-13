from neutron_lib import constants as n_const
from oslo_log import log
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ether
from ryu.lib.packet import arp
from ryu.ofproto import nicira_ext

from dragonflow.db import db_store2
from dragonflow import conf as cfg
from dragonflow.controller.common import constants as const
from dragonflow.controller.common import arp_responder
from dragonflow.controller import df_base_app
from dragonflow.db.models import l2
from dragonflow.controller.common import utils

LOG = log.getLogger(__name__)


class MplsApp(df_base_app.DFlowApp):
    def __init__(self, *args, **kwargs):
        super(MplsApp, self).__init__(*args, **kwargs)
        self.idle_timeout = 30
        self.hard_timeout = 0
        self.mac_address = cfg.CONF.df_mpls.mpls_mac
        self.interface_ip = cfg.CONF.df_mpls.ip_address
        self.mpls_port_id = 18

    def switch_features_handler(self, ev):
        self.add_arp_flow()
        self.set_mpls_ingress_table_flow()
        self.magic_function('tap65111509-0b')

    def add_arp_flow(self):
        #     need to get iface number from ovs
        ofproto = self.datapath.ofproto
        match = self.parser.OFPMatch(in_port=self.mpls_port_id)
        match.set_dl_type(ether.ETH_TYPE_ARP)
        match.set_arp_tpa(utils.ipv4_text_to_int(self.interface_ip))
        match.set_arp_opcode(arp.ARP_REQUEST)

        actions = [self.parser.OFPActionSetField(arp_op=arp.ARP_REPLY),
                   self.parser.NXActionRegMove(src_field='arp_sha',
                                               dst_field='arp_tha',
                                               n_bits=48),
                   self.parser.NXActionRegMove(src_field='arp_sha',
                                               dst_field='eth_dst',
                                               n_bits=48),
                   self.parser.NXActionRegMove(src_field='arp_spa',
                                               dst_field='arp_tpa',
                                               n_bits=32),
                   self.parser.OFPActionSetField(eth_src=self.mac_address),
                   self.parser.OFPActionSetField(arp_sha=self.mac_address),
                   self.parser.OFPActionSetField(arp_spa=self.interface_ip),
                   self.parser.NXActionRegLoad(
                       dst='in_port',
                       ofs_nbits=nicira_ext.ofs_nbits(0, 31),
                       value=0),
                   self.parser.OFPActionOutput(self.mpls_port_id, ofproto.OFPCML_NO_BUFFER)
                   ]

        inst = [self.parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.mod_flow(
            inst=inst,
            match=match,
            table_id=const.INGRESS_CLASSIFICATION_DISPATCH_TABLE,
        )

    def set_mpls_ingress_table_flow(self):
        goto_inst = self.parser.OFPInstructionGotoTable(
            const.INGRESS_MPLS_TABLE)
        inst = [goto_inst]
        self.mod_flow(
            inst=inst,
            match=self.get_mpls_match(),
            table_id=const.INGRESS_CLASSIFICATION_DISPATCH_TABLE,
        )

    def get_mpls_match(self):
        return self.parser.OFPMatch(in_port=self.mpls_port_id, eth_type=ethernet.ether.ETH_TYPE_MPLS)

    def magic_function(self, tap_device_name):
        lport_id = self.vswitch_api.get_port_port_id(tap_device_name)
        LOG.info("port_id for %s: %s", tap_device_name, lport_id)
        lport = self.nb_api.get(l2.LogicalPort(id=lport_id))
        LOG.info("logical port for %s: %r", tap_device_name, lport)
        lswitch = lport.lswitch.get_object()
        if not lswitch:
            lswitch = self.nb_api.get(lport.lswitch)
        network_id = lswitch.unique_key
        self.set_ingress_mpls_flow(network_id, lport)
        self.set_egress_mpls_flow(network_id, '11.10.0.0/24')

    def set_ingress_mpls_flow(self, network_id, lport):
        match = self.get_mpls_match()
        actions = [self.parser.OFPActionPopMpls(ethertype=0x0800),
                   self.parser.OFPActionSetField(eth_dst=lport.mac),
                   self.parser.OFPActionSetField(reg7=lport.unique_key),
                   self.parser.OFPActionSetField(metadata=network_id)]
        action_inst = self.parser.OFPInstructionActions(
            self.ofproto.OFPIT_APPLY_ACTIONS, actions)
        goto_inst = self.parser.OFPInstructionGotoTable(
            const.INGRESS_DISPATCH_TABLE)
        inst = [action_inst, goto_inst]
        self.mod_flow(
            table_id=const.INGRESS_MPLS_TABLE,
            inst=inst,
            match=match,
        )

    def set_egress_mpls_flow(self, network_id, nw_dst):
        match = self.parser.OFPMatch(metadata=network_id, eth_type=ethernet.ether.ETH_TYPE_IP, ipv4_dst=nw_dst)
        actions = [self.parser.OFPActionPushMpls(),
                   self.parser.OFPActionSetField(mpls_label=16),
                   self.parser.OFPActionSetField(eth_src=self.mac_address),
                   self.parser.OFPActionSetField(eth_dst='2c:6b:f5:61:dd:94'),
                   self.parser.OFPActionOutput(self.mpls_port_id, self.datapath.ofproto.OFPCML_NO_BUFFER)]
        inst = [self.parser.OFPInstructionActions(self.datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.mod_flow(
            inst=inst,
            match=match,
            table_id=const.L3_LOOKUP_TABLE
        )
