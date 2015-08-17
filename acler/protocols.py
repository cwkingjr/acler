#!/usr/bin/python

# http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
# When adding protocols here, please consider posting an issue at 
# https://github.com/cwkingjr/aclers

protos = {
    'icmp' : '1',
    'ipv4' : '4',
    'tcp'  : '6',
    'udp'  : '17',
    'ipv6' : '41',
    'gre'  : '47',
    'esp'  : '50',
    'ah'   : '51',
    # Cisco oddity for ah
    'ahp'  : '51',
    'l2tp' : '115',
    'sctp' : '132',
    }


def proto2num(proto):
    """
    Convert a protocol name to the protocol number.
    """
     
    proto = proto.lower()
 
    if proto in protos:
        return protos[proto]
    else:
        msg = "Unknown protocol %s. Please add protocol to acler/protocols.py." % proto
        raise Exception(msg)
