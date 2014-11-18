from pox.core import core
from collections import defaultdict

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_tree
# I need this packet in order to study them.
#import pox.lib.packet as pkt

from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.util import dpidToStr
#I addede them
from pox.lib.packet.ipv4 import ipv4
from pox.lib.revent import EventHalt, EventContinue
from pox.lib.packet.tcp import tcp
# end
from pox.lib.addresses import IPAddr, EthAddr
from collections import namedtuple
import os

log = core.getLogger()


class FiveLayer (EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)
        core.openflow_discovery.addListeners(self)

        # Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
        self.adjacency = defaultdict(lambda:defaultdict(lambda:None))

#       '''     Layer 2
#       BlackList
#       Structure is:   dpid string
#       Devices with the MAC address lsits in here wont get connection
#       '''
        self.blacklist = {EthAddr('00:00:00:00:00:0b')}

#       '''     Layer 3
#       WhiteList
#       Devices with the IP address mention in here will get connection.
#           key=IP source, result is the list of IPs that they can attack
#       '''
        self.ipmap = {  IPAddr('10.0.0.1'): ['10.0.0.2','10.0.0.3','10.0.0.4'],
                        IPAddr('10.0.0.2'): ['10.0.0.1','10.0.0.3','10.0.0.4'],
                        IPAddr('10.0.0.3'): ['10.0.0.1','10.0.0.2'],
                        IPAddr('10.0.0.4'): ['10.0.0.1','10.0.0.2']}


#       '''
#        The structure of self.portmap is a four-tuple key and a string value.
#        The type is:
#        (dpid string, src MAC addr, dst MAC addr, port (int)) -> dpid of next switch
#        '''
        self.portmap = {('00-00-00-00-00-01', EthAddr('00:00:00:00:00:01'),EthAddr('00:00:00:00:00:03'), 80): '00-00-00-00-00-03',
                        #  Add your mapping logic here
                        # VIDEO
                        # h1 --- h3     // there is another rule on top of this
                        ('00-00-00-00-00-03', EthAddr('00:00:00:00:00:01'),EthAddr('00:00:00:00:00:03'), 80): '00-00-00-00-00-04',
                        ('00-00-00-00-00-04', EthAddr('00:00:00:00:00:03'),EthAddr('00:00:00:00:00:01'), 80): '00-00-00-00-00-03',
                        ('00-00-00-00-00-03', EthAddr('00:00:00:00:00:03'),EthAddr('00:00:00:00:00:01'), 80): '00-00-00-00-00-01',
                        # h2 --- h4
                        ('00-00-00-00-00-01', EthAddr('00:00:00:00:00:02'),EthAddr('00:00:00:00:00:04'), 80): '00-00-00-00-00-03',
                        ('00-00-00-00-00-03', EthAddr('00:00:00:00:00:02'),EthAddr('00:00:00:00:00:04'), 80): '00-00-00-00-00-04',
                        ('00-00-00-00-00-04', EthAddr('00:00:00:00:00:04'),EthAddr('00:00:00:00:00:02'), 80): '00-00-00-00-00-03',
                        ('00-00-00-00-00-03', EthAddr('00:00:00:00:00:04'),EthAddr('00:00:00:00:00:02'), 80): '00-00-00-00-00-01',
                        # h1 -- h4
                        ('00-00-00-00-00-01', EthAddr('00:00:00:00:00:01'),EthAddr('00:00:00:00:00:04'), 80): '00-00-00-00-00-03',
                        ('00-00-00-00-00-03', EthAddr('00:00:00:00:00:01'),EthAddr('00:00:00:00:00:04'), 80): '00-00-00-00-00-04',
                        ('00-00-00-00-00-04', EthAddr('00:00:00:00:00:04'),EthAddr('00:00:00:00:00:01'), 80): '00-00-00-00-00-03',
                        ('00-00-00-00-00-03', EthAddr('00:00:00:00:00:04'),EthAddr('00:00:00:00:00:01'), 80): '00-00-00-00-00-01',
                        # h2 -- h3
                        ('00-00-00-00-00-01', EthAddr('00:00:00:00:00:02'),EthAddr('00:00:00:00:00:03'), 80): '00-00-00-00-00-03',
                        ('00-00-00-00-00-03', EthAddr('00:00:00:00:00:02'),EthAddr('00:00:00:00:00:03'), 80): '00-00-00-00-00-04',
                        ('00-00-00-00-00-04', EthAddr('00:00:00:00:00:03'),EthAddr('00:00:00:00:00:02'), 80): '00-00-00-00-00-03',
                        ('00-00-00-00-00-03', EthAddr('00:00:00:00:00:03'),EthAddr('00:00:00:00:00:02'), 80): '00-00-00-00-00-01',
                        # 0 PORT
                        # h1 -- h3
                        ('00-00-00-00-00-01', EthAddr('00:00:00:00:00:01'),EthAddr('00:00:00:00:00:03'), 0): '00-00-00-00-00-02',
                        ('00-00-00-00-00-02', EthAddr('00:00:00:00:00:01'),EthAddr('00:00:00:00:00:03'), 0): '00-00-00-00-00-04',
                        ('00-00-00-00-00-04', EthAddr('00:00:00:00:00:03'),EthAddr('00:00:00:00:00:01'), 0): '00-00-00-00-00-02',
                        ('00-00-00-00-00-02', EthAddr('00:00:00:00:00:03'),EthAddr('00:00:00:00:00:01'), 0): '00-00-00-00-00-01',
                        # h2 -- h4
                        ('00-00-00-00-00-01', EthAddr('00:00:00:00:00:02'),EthAddr('00:00:00:00:00:04'), 0): '00-00-00-00-00-02',
                        ('00-00-00-00-00-02', EthAddr('00:00:00:00:00:02'),EthAddr('00:00:00:00:00:04'), 0): '00-00-00-00-00-04',
                        ('00-00-00-00-00-04', EthAddr('00:00:00:00:00:04'),EthAddr('00:00:00:00:00:02'), 0): '00-00-00-00-00-02',
                        ('00-00-00-00-00-02', EthAddr('00:00:00:00:00:04'),EthAddr('00:00:00:00:00:02'), 0): '00-00-00-00-00-01',
                        # h1 -- h4
                        ('00-00-00-00-00-01', EthAddr('00:00:00:00:00:01'),EthAddr('00:00:00:00:00:04'), 0): '00-00-00-00-00-02',
                        ('00-00-00-00-00-02', EthAddr('00:00:00:00:00:01'),EthAddr('00:00:00:00:00:04'), 0): '00-00-00-00-00-04',
                        ('00-00-00-00-00-04', EthAddr('00:00:00:00:00:04'),EthAddr('00:00:00:00:00:01'), 0): '00-00-00-00-00-02',
                        ('00-00-00-00-00-02', EthAddr('00:00:00:00:00:04'),EthAddr('00:00:00:00:00:01'), 0): '00-00-00-00-00-01',
                        # h2 -- h3
                        ('00-00-00-00-00-01', EthAddr('00:00:00:00:00:02'),EthAddr('00:00:00:00:00:03'), 0): '00-00-00-00-00-02',
                        ('00-00-00-00-00-02', EthAddr('00:00:00:00:00:02'),EthAddr('00:00:00:00:00:03'), 0): '00-00-00-00-00-04',
                        ('00-00-00-00-00-04', EthAddr('00:00:00:00:00:03'),EthAddr('00:00:00:00:00:02'), 0): '00-00-00-00-00-02',
                        ('00-00-00-00-00-02', EthAddr('00:00:00:00:00:03'),EthAddr('00:00:00:00:00:02'), 0): '00-00-00-00-00-01'
                       }


    def _handle_LinkEvent (self, event):
        l = event.link
        sw1 = dpid_to_str(l.dpid1)
        sw2 = dpid_to_str(l.dpid2)

        log.debug ("link %s[%d] <-> %s[%d]",
                   sw1, l.port1,
                   sw2, l.port2)

        self.adjacency[sw1][sw2] = l.port1
        self.adjacency[sw2][sw1] = l.port2


    def _handle_PacketIn (self, event):
#        """        Handle packet in messages from the switch to implement above algorithm.        """
        packet = event.parsed
        tcpp = event.parsed.find('tcp')

        def install_fwdrule(event,packet,outport):
            msg = of.ofp_flow_mod()
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.match = of.ofp_match.from_packet(packet, event.port)
            # ofp_action_output is only for issue the output port
            msg.actions.append(of.ofp_action_output(port = outport))
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)

        def forward (message = None):
            this_dpid = dpid_to_str(event.dpid)

            #   ""
            #   Layer 2 - Primer paso de mi proyecto
            #   ""
            if packet.dst.is_multicast:
                flood()
                return
            elif packet.src in self.blacklist:  # or self.blacklist(packet.dst):
                # We have seen a packet in our MAC backlist that must be droped.
                log.debug("L2: BLOCKED: Malicious HOST try to communicate (IN/OUT). MAC address has been blocked: %s" % str(packet.src))
                log.debug("L2: BLOCKED: Its traffic will be dropped")
                #  https://github.com/nemethf/sigcomm2013/blob/master/our_controller/predefined_routing.py
                return
            else:
                log.debug("Got unicast packet for %s at %s (input port %d):",
                          packet.dst, dpid_to_str(event.dpid), event.port)
            #   ""
            #   Layer 2 - End of the first part of my project
            #   ""

                try:
                    #   ""
                    #   Layer 3 - Second part of my code
                    #   ""
                    
                    if event.parsed.find('icmp'):
                        # ICMP packets or PING packets will be alowed to be transmitted.
                        # if we do not anything, it will flood anyway, but we like to have everything tight
                        log.debug("L3: ICMP: ICMP packet. They are always free to travel, packet will be flood")
                        log.debug("L3: ICMP: Source IP: %s / Destination IP: %s" % (str(event.parsed.find('icmp').srcip), str(event.parsed.find('icmp').dstip)))
                        # flood the packet
                        install_fwdrule(event,packet,of.OFPP_FLOOD)
                        #flood()
                        return

                    # if the flow is contained in my list above, it will be allowed 
                    ipv4_packet = event.parsed.find('ipv4')
                    if not self.ipmap.get(ipv4_packet.srcip):   # IP source is not in our list
                        log.debug("L3: Packet blocked. Source IP address is not allowed: Source IP: %s" % str(ipv4_packet.srcip))
                        return
                    elif not str(ipv4_packet.dstip) in self.ipmap[ipv4_packet.srcip]:   # combination IP source-destination is not mentioned.
                        log.debug("L3: BLOCKED: Packet blocked. Source IP address is OK but it cannot send traffic to the destination address:")
                        log.debug("L3: BLOCKED: Source IP: %s / Destination IP: %s" % (str(ipv4_packet.srcip), str(ipv4_packet.dstip)))
                        return
                    else:   # IP source is allowed and combination between host is allowed as well.
                        log.debug("L3: OK: Packet is allowed to travel. Combination source/destination IP is allowed")
                        log.debug("L3: OK: Source IP: %s / Destination IP: %s" % (str(ipv4_packet.srcip), str(ipv4_packet.dstip)))
                    #   ""
                    #   Layer 3 - End of the second part of my code
                    #   ""

                    #   ""
                    #   Layer 4 - Third part of my code
                    #   ""
                    k = (this_dpid, packet.src, packet.dst, packet.find('tcp').dstport)

                    if not self.portmap.get(k):     #   We could not find it in our portmap list
                        k = (this_dpid, packet.src, packet.dst, packet.find('tcp').srcport)
                        if not self.portmap.get(k):
                            raise AttributeError
                    ndpid = self.portmap[k]
                    log.debug("L5: INSTALLING RULE: install: %s output %d" % (str(k), self.adjacency[this_dpid][ndpid]))
                    install_fwdrule(event,packet,self.adjacency[this_dpid][ndpid])

                    #   ""
                    #   Layer 4 - end Third part of my code
                    #   ""
                    


                    #   ""
                    #   layer 5
                    #   ""
                    wordforbidden = ["wikipedia", "facebook"]
#                    log.debug("!!!!!!!!!!!!!!PACKET TCP %s" % (str(packet.payload)))
#                    log.debug("!!!!!!!!!!!!!!PACKET TCP %s" % (str(packet.next.next.msg)))
#                    log.debug("!!!!!!!!!!!!!!PACKET TCP %s" % (str(packet.next.next.raw)))
                    log.debug("L5: OK: FIRST APPROACH")
                    if ((this_dpid == ('00-00-00-00-00-03')) and (packet.find('tcp')) and (str(packet.next.next.payload))is not None):
                        TCPpayload = str(packet.next.next.payload)
                        log.debug("L5: OK: DENTRO del switch numero 3!!!")
                        for i in range(len(wordforbidden)):
                            if wordforbidden[i] in TCPpayload:
                                log.debug("L5: ALARM: SWITCH %s" % this_dpid)
                                log.debug("L5: ALARM: TCP PACKET's payload contains: %s" % wordforbidden[i])
#                    log.debug("!!!!!!!!!!!!!!PACKET TCP %s" % (str(packet.next.next.payload)))
                    #   ""
                    #   layer 5 - End 
                    #   ""
                    return
                except AttributeError:
                    log.debug("packet type has no transport ports, flooding")
                    # flood and install the flow table entry for the flood
                    install_fwdrule(event,packet,of.OFPP_FLOOD)

        # flood, but don't install the rule
        def flood (message = None):
            #""" Floods the packet """
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)

        forward()


    def _handle_ConnectionUp(self, event):
        dpid = dpidToStr(event.dpid)
        log.debug("Switch %s has come up.", dpid)
        

def launch():
    # Run spanning tree so that we can deal with topologies with loops
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()

#    '''    Starting the Video Slicing module    '''
    core.registerNew(FiveLayer)
