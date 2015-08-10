#!/usr/bin/python

# Custom (but limited) cisco acl parser since the customer
# has new configuration control procedures around globally
# installing binaries or python modules, which using acl
# requires. Using a custom parser, although more limited,
# will save potential months of approval wait time.

from acleritem import AclerItem
from protocols import protos

tokens = None # token list
current_token = 0 # index

class Endpoint(object):
    """Just holding some data values for readability"""

    def __init__(self):
        self.has_netblock = False
        self.has_port = False
        self.netblock = None
        self.port = None

    def __repr__(self):
        return "<Endpoint: has_netblock %s, has_port %s, netblock %s, port %s >" % (
               self.has_netblock, self.has_port, self.netblock, self.port)


def get_port(mye):

    global current_token

    tokenwatch = len(tokens) - 1

    # eq 25
    if tokens[current_token] == 'eq':
        mye.has_port = True
        mye.port = tokens[current_token + 1]
        # move the index to the next endpoint
        if tokenwatch >= current_token + 2:
            current_token += 2

    # range 20 21
    elif tokens[current_token] == 'range':
        mye.has_port = True
        mye.port = "%s-%s" % (tokens[current_token + 1], tokens[current_token + 2])
        # move the index to the next endpoint
        if tokenwatch >= current_token + 3:
            current_token += 3


def is_dotted_quad(quad):
    """Make sure the value is a dotted quad for ipv4; 2.2.2.2"""

    quad = quad.strip()

    try:
        parts = quad.split('.')
    except:
        return False

    if len(parts) != 4:
        return False

    # make sure all numbers are 0-255
    for i in parts:
        if not 0 <= int(i) <= 255:
            return False

    return True


def count_bits_set(myint):
    """ Count the number of one bits set in the number """

    count = 0

    while(myint):
        # add 1 if the bit is set
        count += (myint & 1)
        # shift the number over one
        myint >>= 1

    return count


def inverse_mask_to_cidr(imask):
    """
    Use bitwise operations to determine the cidr number for
    a Cisco ipv4 inverse dotted quad network mask.
    Example: change 0.0.255.255 to 16
    """

    # subtract each octet from 255 to get the inverted number
    (a,b,c,d) = [255 - int(x) for x in imask.split('.')]
    # convert the octets to a single number mask
    intmask = (a<<24) + (b<<16) + (c<<8) + d
    # convert the number mask to the cidr number
    cidr = count_bits_set(intmask)
    return cidr


def get_endpoint():

    global current_token

    e = Endpoint() 

    v = tokens[current_token]

    if v == 'any': 
        # any [eq 25 | range 21 22]
        e.has_netblock = False
        current_token += 1
        get_port(e)
    elif v == 'host':
        # host 2.2.2.2 [eq 25 | range 21 22]
        e.has_netblock = True
        e.netblock = tokens[current_token + 1]
        if len(tokens) - 1 >= current_token + 2:
            current_token += 2
            get_port(e)
    elif is_dotted_quad(v) and is_dotted_quad(tokens[current_token + 1]):
        # 2.2.0.0 0.0.255.255 [eq 25 | range 21 22]
        e.has_netblock = True
        addr = v
        mask = inverse_mask_to_cidr(tokens[current_token + 1])
        e.netblock = "%s/%s" % (addr, mask)
        if len(tokens) - 1 >= current_token + 2:
            current_token += 2
            get_port(e)

    return e


def parse_cisco(cisco_acl_line): 
    """
    Parse the Cisco-formatted ACL entry and return a populated AclerItem class.
    """

    global current_token, tokens

    myacler = AclerItem(cisco_acl_line) 

    if not cisco_acl_line.startswith('access-list'):
        myacler.error = 'Line does not start with access-list'
        return myacler

    if not 'permit' in cisco_acl_line.lower():
        myacler.error = 'Line does not include permit'
        return myacler

    if '/' in cisco_acl_line.lower():
        myacler.error = 'Format issue, forward slash seen'
        return myacler

    if 'remark' in cisco_acl_line.lower():
        try:
            # pull info from second "access-list" to end and use that
            noremark = "access-list %s" % cisco_acl_line.split('access-list')[2].strip()
            cisco_acl_line = noremark
        except:
            myacler.error = 'Could not parse remark line'
            return myacler

    try:
        myacler.parsed = True

        # strip off the newline
        myline = cisco_acl_line.strip()

        # split on space
        tokens = myline.split()

        try:
            x = int(tokens[1])
        except:
            myacler.parsed = False
            myacler.error = "ACL number is not an integer: %s" % tokens[1]
            return myacler

        if not tokens[3] in protos:
            myacler.parsed = False
            myacler.error = "Protocol %s not in protos. Please add to protocols.protos." % tokens[3]
            return myacler

        current_token = 4
        source = get_endpoint()
        dest   = get_endpoint()

        if source.has_netblock == False and dest.has_netblock == False:
            myacler.parsed = False
            myacler.error = 'No source or dest network address'
        else:

            # load source info
            if source.has_netblock:
                myacler.sip = source.netblock
            if source.has_port:
                myacler.sport = source.port 

            # load dest info
            if dest.has_netblock:
                myacler.dip = dest.netblock
            if dest.has_port:
                myacler.dport = dest.port 

    except Exception as e:
        myacler.parsed = False
        myacler.error = str(e)

    return myacler
