from oslo_log import log
from ryu.lib.packet import ethernet
from ryu.ofproto import ether
from ryu.lib.packet import arp
from ryu.ofproto import nicira_ext

from dragonflow import conf as cfg
from dragonflow.controller.common import constants as const
from dragonflow.controller import df_base_app
from dragonflow.db.models import l2
from dragonflow.db.models import constants as model_constants
from dragonflow.db.models import remote_routes
from dragonflow.controller.common import utils

LOG = log.getLogger(__name__)


class MplsApp(df_base_app.DFlowApp):
    def __init__(self, *args, **kwargs):
        super(MplsApp, self).__init__(*args, **kwargs)
        self.idle_timeout = 30
        self.hard_timeout = 0
        self.mac_address = cfg.CONF.df_mpls.mpls_mac
        self.interface_ip = cfg.CONF.df_mpls.ip_address
        self.mpls_port_id = 1
        # Need to fix this - use ARP to the the next hop MAC
        self.remote_router_mac = {'10.11.132.19': '2c:6b:f5:61:dd:94', '10.10.132.19': '2c:6b:f5:61:dd:94'}

    def switch_features_handler(self, ev):
        self.add_arp_flow()
        self.set_mpls_ingress_table_flow()

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

    def get_mpls_label_match(self, label):
        return self.parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_MPLS, mpls_label=label)

    @df_base_app.register_event(remote_routes.LocalLabeledRoute, model_constants.EVENT_CREATED)
    def local_route_setup_create(self, llroute):
        LOG.debug('got local route create event for %s', llroute)
        self._setup_local_route(llroute)

    @df_base_app.register_event(remote_routes.LocalLabeledRoute, model_constants.EVENT_DELETED)
    def local_route_setup_remove(self, llroute):
        LOG.debug('got local route remove event for %s', llroute)
        self._delete_local_route(llroute.label)

    @df_base_app.register_event(remote_routes.RemoteLabeledRoute, model_constants.EVENT_CREATED)
    def remote_route_setup_create(self, rlroute):
        LOG.debug('got remote route create event - %s %s %s %s', rlroute.destination, rlroute.helper_port,
                  rlroute.nexthop, rlroute.label)
        net_id = self._get_net_id(rlroute.helper_port)
        self.add_egress_mpls_flow(net_id, rlroute)

    @df_base_app.register_event(remote_routes.RemoteLabeledRoute, model_constants.EVENT_DELETED)
    def remote_route_setup_remove(self, rlroute):
        LOG.debug('got remote route remove event - %s %s %s %s', rlroute.destination, rlroute.helper_port,
                  rlroute.nexthop, rlroute.label)
        net_id = self._get_net_id(rlroute.helper_port)
        self.remove_egress_mpls_flow(net_id, rlroute)

    def _setup_local_route(self, llroute):
        lport = self.nb_api.get(l2.LogicalPort(id=llroute.port))

        lswitch = lport.lswitch.get_object()
        if not lswitch:
            lswitch = self.nb_api.get(lport.lswitch)

        network_id = lswitch.unique_key
        match = self.get_mpls_label_match(llroute.label)
        actions = [self.parser.OFPActionPopMpls(ethertype=ethernet.ether.ETH_TYPE_IP),
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
            priority=const.PRIORITY_HIGH,
            inst=inst,
            match=match,
        )

    def _delete_local_route(self, label):
        match = self.get_mpls_label_match(label)
        self.mod_flow(
            table_id=const.INGRESS_MPLS_TABLE,
            command=self.datapath.ofproto.OFPFC_DELETE,
            priority=const.PRIORITY_HIGH,
            match=match)

    def _get_net_id(self, port_id):
        lport = self.nb_api.get(l2.LogicalPort(id=port_id))
        lswitch = lport.lswitch.get_object()
        if not lswitch:
            lswitch = self.nb_api.get(lport.lswitch)
        return lswitch.unique_key

    def add_egress_mpls_flow(self, network_id, rlroute):
        match = self._get_remote_route_match(network_id, rlroute)
        actions = [self.parser.OFPActionPushMpls(),
                   self.parser.OFPActionSetField(mpls_label=rlroute.label),
                   self.parser.OFPActionSetField(eth_src=self.mac_address),
                   self.parser.OFPActionSetField(eth_dst=self.remote_router_mac[rlroute.nexthop.__str__()]),
                   self.parser.OFPActionOutput(self.mpls_port_id, self.datapath.ofproto.OFPCML_NO_BUFFER)]
        inst = [self.parser.OFPInstructionActions(self.datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.mod_flow(
            inst=inst,
            match=match,
            table_id=const.L3_LOOKUP_TABLE,
            priority=const.PRIORITY_HIGH,
        )

    def remove_egress_mpls_flow(self, network_id, rlroute):
        match = self._get_remote_route_match(network_id, rlroute)
        self.mod_flow(
            table_id=const.L3_LOOKUP_TABLE,
            command=self.datapath.ofproto.OFPFC_DELETE,
            priority=const.PRIORITY_HIGH,
            match=match)

    def _get_remote_route_match(self, network_id, rlroute):
        return self.parser.OFPMatch(metadata=network_id, eth_type=ethernet.ether.ETH_TYPE_IP,
                                    ipv4_dst=rlroute.destination.__str__())
