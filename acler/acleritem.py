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
        self.sip = None
        self.dip = None
        self.dport = None
        self.sport = None
        self.protocol = None
        self.parsed = False
        self.line = None
        self.error = None
        self.track = dict() # track counts
        self.assess = False
        self.silk_criteria_cache = None
        self.silk_criteria_reversed_cache = None

        if acl is None or acl == '':
            raise ValueError("One Cisco-formatted ACL line required")
        else:
            self.acl = acl.strip()

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

        return "Line %s|Traffic %s|%s|%s\n" % \
            (self.line, self.get_types_with_records(), self.acl, self.format_track())

    def dump_no_traffic(self):
        """Dump record in format needed for has no traffic output file entry"""

        return "Line %s|No Traffic|%s\n" % (self.line, self.acl)

    def dump_no_assess(self):
        """Dump record in format needed for not assessed output file entry"""

        return "Line %s|Not Assessed|%s|error %s\n" % (self.line, self.acl, self.error)

    def get_csv_out_prefix(self):
        """Dump record info as a list to add to /prefix the CSV infile data"""

        ret = list()

        if self.has_records():                                                                                                                    
            # traffic
            msg = "Traffic|%s|%s" % (self.get_types_with_records(), self.format_track())
            ret.append(msg)
            return ret
        elif self.assess and not self.has_records():
            # no traffic
            msg = "No Traffic||"
            ret.append(msg)
            return ret
        elif not self.assess:
            # not assessed
            msg = "Not Assessed||error %s" % self.error
            ret.append(msg)
            return ret
        else:
            # unknown problem
            msg = "Unknown acler results||"
            ret.append(msg)
            return ret

    def get_silk_criteria(self):
        """
        Convert the contained variable values into a pysilk query string.
        """

        if self.silk_criteria_cache:
            return self.silk_criteria_cache

        items = list()

        if self.sip is not None:
            items.append("rec.sip in IPWildcard('%s')" % self.sip)

        if self.sport is not None:
            if '-' in self.sport:
                (first, last) = self.sport.split('-')
                items.append("rec.sport in [%s,%s]" % (first, last))
            else:
                items.append("rec.sport == %s" % self.sport)

        if self.dip is not None:
            items.append("rec.dip in IPWildcard('%s')" % self.dip)

        if self.dport is not None:
            if '-' in self.dport:
                (first, last) = self.dport.split('-')
                items.append("rec.dport in [%s,%s]" % (first, last))
            else:
                items.append("rec.dport == %s" % self.dport)

        criteria = ' and '.join(items)

        self.silk_criteria_cache = criteria

        return criteria


    def get_silk_reversed_criteria(self):
        """
        Convert the contained variable values into a reversed pysilk query string.
        """

        if self.silk_criteria_reversed_cache:
            return self.silk_criteria_reversed_cache

        items = list()

        if self.sip is not None:
            items.append("rec.dip in IPWildcard('%s')" % self.sip)

        if self.sport is not None:
            if '-' in self.sport:
                (first, last) = self.sport.split('-')
                items.append("rec.dport in [%s,%s]" % (first, last))
            else:
                items.append("rec.dport == %s" % self.sport)

        if self.dip is not None:
            items.append("rec.sip in IPWildcard('%s')" % self.dip)

        if self.dport is not None:
            if '-' in self.dport:
                (first, last) = self.dport.split('-')
                items.append("rec.sport in [%s,%s]" % (first, last))
            else:
                items.append("rec.sport == %s" % self.dport)

        criteria = ' and '.join(items)

        self.silk_criteria_reversed_cache = criteria

        return criteria


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

