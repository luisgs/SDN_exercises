'''
Coursera:
- Software Defined Networking (SDN) course
-- Network Virtualization

Professor: Nick Feamster
Teaching Assistant: Arpit Gupta
'''

from pox.core import core
from collections import defaultdict

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_tree

from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr
from collections import namedtuple
import os

log = core.getLogger()


class TopologySlice (EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)
        log.debug("Enabling Slicing Module")
        
        
    """This event will be raised each time a switch will connect to the controller"""
    def _handle_ConnectionUp(self, event):
        
        # Use dpid to differentiate between switches (datapath-id)
        # Each switch has its own flow table. As we'll see in this 
        # example we need to write different rules in different tables.
	dpid = dpidToStr(event.dpid)
        log.debug("Switch %s has come up.", dpid)
        """ Add your logic here """
	# We load openflow entries depending of the switch dpid.
	# rememeber that this function is trigered every time a switch is connected to the controller.
        if ( dpid == '00-00-00-00-00-01' ):
            msg_1p1 = of.ofp_flow_mod()
            msg_1p1.match.in_port = 1
            msg_1p1.actions.append(of.ofp_action_output(port = 3))
            log.info("Rule for %s and port %i", dpidToStr(event.dpid), msg_1p1.match.in_port)	
	    # send the rule to the switch
            event.connection.send(msg_1p1)

	    # inPort - 3
            # we also are able to declare everything in one line as follow:
            msg_1p3 = of.ofp_flow_mod(	match = of.ofp_match ( in_port = 3), 
					action = of.ofp_action_output (port = 1))
            event.connection.send(msg_1p3)
	    # inPort - 2
  	    msg_1p2 = of.ofp_flow_mod(	match = of.ofp_match ( in_port = 2),
					action = of.ofp_action_output (port = 4))
            event.connection.send(msg_1p2)
	    # inPort - 4
            msg_1p4 = of.ofp_flow_mod(	match = of.ofp_match ( in_port = 4),
					action = of.ofp_action_output(port = 2))
            event.connection.send(msg_1p4)
        elif ( event.dpid == 4 ):	# I can also use dpid as Integer
	    # 1 to 3
            msg_4p1 = of.ofp_flow_mod(	match = of.ofp_match ( in_port = 1), 
					action = of.ofp_action_output (port = 3))
            event.connection.send(msg_4p1)
	    # 3 to 1
            msg_4p3 = of.ofp_flow_mod(	match = of.ofp_match ( in_port = 3), 
					action = of.ofp_action_output (port = 1))
            event.connection.send(msg_4p3)
            # 2 to 4
            msg_4p2 = of.ofp_flow_mod(	match = of.ofp_match ( in_port = 2), 
					action = of.ofp_action_output (port = 4))
            event.connection.send(msg_4p2)
	    # 4 to 2
            msg_4p4 = of.ofp_flow_mod(	match = of.ofp_match ( in_port = 4), 
					action = of.ofp_action_output (port = 2))
            event.connection.send(msg_4p4)
#        elif ( dpid == '00-00-00-00-00-02' ) or ( dpid == '00-00-00-00-00-03' ):
	else:
           msg = of.ofp_flow_mod()
           msg.match.in_port = 1
           msg.actions.append(of.ofp_action_output(port = 2))
           event.connection.send(msg)

           msg = of.ofp_flow_mod()
           msg.match.in_port = 2
           msg.actions.append(of.ofp_action_output(port = 1))
           event.connection.send(msg)

def launch():
    # Run spanning tree so that we can deal with topologies with loops
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()

    '''
    Starting the Topology Slicing module
    '''
    core.registerNew(TopologySlice)
