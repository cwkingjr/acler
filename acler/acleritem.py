#!/usr/bin/python

class AclerItem(object):
    """
    Class to hold acler data elements
    """

    """
    Just using this as a simple data container. Not restricting direct
    entry into attributes via property decorators, etc.
    """

    def __init__(self, acl):

        # acl criteria
        self.sip = None
        self.dip = None
        self.dport = None
        self.sport = None
        self.protocol = None

        # logic tags
        self.parsed = False
        self.line = None
        self.error = None
        self.track = dict() # track counts
        self.assessible = False
        self.num_days_checked = 0 # repo days checked for this traffic
        self.finished = False

        # cachees
        self.rwfilter_criteria_cache = None
        self.rwfilter_criteria_reversed_cache = None

        if acl is None or acl == '':
            raise ValueError("One Cisco-formatted ACL line required")
        else:
            self.acl = acl.strip()

    def assess(self):
        """Do we need to check the repo for this ACL criteria"""

        if self.has_records():
            self.finished = True

        if self.finished:
            return False

        if self.assessible:
            return True

        # if the acl was parsed and at least one side has an address
        if self.parsed and self.error is None:
            if self.sip is not None or self.dip is not None:
                self.assessible = True
                return True
            else:
                self.error = 'Not assessed due to no sip or dip block'
                return False


    def add_track(self, typename, counttype, count):
        """Push type-specific counts to a dict of dicts"""

        if typename not in self.track:
            # initialize with dict for Records, Bytes, and Packets
            # plus Reversed Records, Reversed Bytes, and Reversed Packets
            self.track[typename] = { 'FR': 0, 'FB': 0, 'FP': 0, 'RR': 0, 'RB': 0, 'RP': 0 }
            
        self.track[typename][counttype] += count


    def __repr__(self):

        return "<AclerItem: line %s, acl %s, %s>" % (self.line, self.acl, self.format_track())


    def has_records(self):
        """Return True if this item has any silk record data"""

        for k in self.track:
            mydict = self.track[k]
            for key in mydict:
                if key in ('FR','RR'):
                    if mydict[key] != 0:
                        return True
        return False


    def get_types_with_records(self):
        """Returns string of names of silk types that had records"""

        s = set()

        for silktype in self.track:
            mydict = self.track[silktype]
            for key in mydict:
                val = mydict[key]
                if key in ('FR','RR'):
                    if mydict[key] != 0:
                        s.add(silktype)

        return ' '.join(sorted(s))


    def format_track(self):
        """Convert the track dict to a readable string"""

        s = ''

        for silktype in sorted(self.track):

            # grab these for bytes/packet math
            forward_packets = 0
            reverse_packets = 0
            forward_bytes = 0
            reverse_bytes = 0

            s += " %s[" % silktype
            mydict = self.track[silktype]
            for key in sorted(mydict):
                val = mydict[key]

                if key == 'FB': forward_bytes = val
                if key == 'RB': reverse_bytes = val
                if key == 'FP': forward_packets = val
                if key == 'RP': reverse_packets = val

                # only include counts that are not zero for clarity/space
                if not val == 0:
                    s += "%s=%d " % (key, val)

            # add in the bytes/packet info
            if forward_packets != 0:
                AFBP = forward_bytes / forward_packets
                s += "FB/FP=%d " % AFBP

            if reverse_packets != 0:
                ARBP = reverse_bytes / reverse_packets
                s += "RB/RP=%d " % ARBP

            s = s.rstrip()
            s += "]"

        return s


    def dump(self):

        return "<AclerItem: line %s, acl %s, parsed %s, error %s, assess %s, " \
            "protocol %d, sip %s, sport %s, dip %s, dport %s,%s>" % \
            (self.line, self.acl, self.parsed, self.error, self.assess, \
            self.protocol, self.sip, self.sport, self.dip, self.dport, \
            self.format_track())

    def dump_traffic(self):
        """Dump record in format needed for has traffic output file entry"""

        return "%s|Traffic %s|%s|%s\n" % \
            (self.line, self.get_types_with_records(), self.acl, self.format_track())

    def dump_no_traffic(self):
        """Dump record in format needed for has no traffic output file entry"""

        return "%s|No Traffic|%s\n" % (self.line, self.acl)

    def dump_no_assess(self):
        """Dump record in format needed for not assessed output file entry"""

        return "%s|Not Assessed|%s|error %s\n" % (self.line, self.acl, self.error)

    def get_csv_out_prefix(self):
        """Dump record info as a list to add to/prefix the CSV infile data"""

        ret = list()

        if self.has_records():                                                                                                                    
            # traffic
            msg = "%s,Traffic|%s|%s" % (self.line, self.get_types_with_records(), self.format_track())
            ret.append(msg)
            return ret
        elif self.assess and not self.has_records():
            # no traffic
            msg = "%s,No Traffic||" % self.line
            ret.append(msg)
            return ret
        elif not self.assess:
            # not assessed
            msg = "%s,Not Assessed||error %s" % (self.line, self.error)
            ret.append(msg)
            return ret
        else:
            # unknown problem
            msg = "%s,Unknown acler results||" % self.line
            ret.append(msg)
            return ret

    def get_rwfilter_criteria(self):
        """
        Convert the contained variable values into an rwfilter query string.
        """

        if self.rwfilter_criteria_cache:
            return self.rwfilter_criteria_cache

        items = list()
        items.append('rwfilter')

        if self.protocol is not None:
            items.append("--protocol=%s" % self.protocol)

        if self.sip is not None:
            items.append("--saddress=%s" % self.sip)

        if self.sport is not None:
            items.append("--sport=%s" % self.sport)

        if self.dip is not None:
            items.append("--daddress=%s" % self.dip)

        if self.dport is not None:
            items.append("--dport=%s" % self.dport)

        self.rwfilter_criteria_cache = items

        # passing back a list
        return items


    def get_rwfilter_reversed_criteria(self):
        """
        Convert the contained variable values into a reversed
        rwfilter query string.
        """

        if self.rwfilter_criteria_reversed_cache:
            return self.rwfilter_criteria_reversed_cache

        items = list()
        items.append('rwfilter')

        if self.protocol is not None:
            items.append("--protocol=%s" % self.protocol)

        if self.sip is not None:
            items.append("--daddress=%s" % self.sip)

        if self.sport is not None:
            items.append("--dport=%s" % self.sport)

        if self.dip is not None:
            items.append("--saddress=%s" % self.dip)

        if self.dport is not None:
            items.append("--sport=%s" % self.dport)

        self.rwfilter_criteria_reversed_cache = items

        return items


    def smallest_ip_block(self):
        """
        Return the sip or dip, whichever is the smallest network address block. For use in building netflow set
        file to pull rwquery using a set of the addresses from one side of each acl permit.
        """

        if self.sip is None and self.dip is None:
            # in this case, the netflow criteria would need to work with any any
            # and use ports / protocol as the criteria
            return None
        elif self.sip is None: return self.dip
        elif self.dip is None: return self.sip
        # if it's just a single host address just use it 
        elif not '/' in self.sip: return self.sip
        # if it's just a single host address just use it 
        elif not '/' in self.dip: return self.dip
        # figure out which side has the smaller cidr
        else:
            # example 2.2.2.0/24
            sipcidr = int(self.sip.split('/')[1])
            dipcidr = int(self.dip.split('/')[1])
            # pick the largest number, which is the smallest block
            if sipcidr >= dipcidr:
                return self.sip
            else:
                return self.dip

