#!/usr/bin/python

# See license file for license info
# https://github.com/cwkingjr/acler/

from __future__ import print_function
# originally used https://github.com/jathanism/acl library but abandoned
# and created limited custom acl parser due to time/policy limitations around
# getting site-packages modules installed at customer location
from acler.acleritem import AclerItem
from acler.cisco_custom import parse_cisco
from acler.elapsed_time import elapsed_time                                                                                                        
import csv
from datetime import datetime, date, timedelta
import logging, logging.handlers
# not a best practice to import all, but what is called for by SEI docs
from silk import *
import optparse
import os
from os.path import expanduser
import re
import subprocess
import sys
import time

# global vars
aclers = list() # list of AclerItem objects
setfile = None # silk set file
mytime = None # clean datetime info for inclusion in file names
rwfile = None # rwf working file
tmprwfile = None # rwf working file for each acl check
desired_types = list() # silk types to track
options = None # option parsing
args = None # option parsing
logger = None # logging handler


def build_set():
    """
    Build a silk set of the smallest ip block (sip or dip) from
    each assessible acl record. This will be used by the 
    rwfilter pull to build a working file of the traffic we
    need to analyze. This is instead of hitting the repo 
    numerous times.
    """

    global setfile

    # gather up the smallest ip block from each acl
    blocks = list()
    for i in aclers:
        if i.assess():
            a = i.smallest_ip_block()
            blocks.append(a)

    # build a set file
    myset = IPSet(blocks)
    logger.debug("Saving ACL SiLK set file at: %s" % setfile)
    myset.save(setfile)


def aclfile_to_aclers(aclfilename):
    """
    Read the lines in the acl file and convert each line to an
    AclerItem, adding each AclerItem to the aclers list.
    """

    logger.info("Processing %s using column %d for ACL entries." % (aclfilename, options.infilecolumn))

    with open(aclfilename, 'rb') as f:

        reader = csv.reader(f) 

        # enumerate provides index and value
        for i,v in enumerate(reader):
            i = i + 1 # make one based

            # make sure there are enough columns in the row
            if options.infilecolumn > len(v):
                msg = "Row %d does not have enough sections to process col %d: %s" % (i, options.infilecolumn, v)
                logger.error(msg)
                myname = ' '.join(v)
                myacler = AclerItem(myname)
                try:
                    # try to get a line number from first col
                    myint = v[0].strip()
                    # make sure it's an int
                    myint = int(myint)
                    myacler.line = str(myint) 
                except:
                    # craft a line number that won't conflict with csv first col numbers
                    myacler.line = str(i + 2000000)
                    logger.debug("Using crafted line number %d for line with too few cols: %s" % 
                                (myacler.line, v))
                myacler.error = msg
                aclers.append(myacler)
                continue

            # convert to zero based for the list
            col = options.infilecolumn - 1

            try:
                myacler = parse_cisco(v[col])
                aclers.append(myacler)
                # try to get a line number from first col
                myint = v[0].strip()
                # make sure it's an int
                myint = int(myint)
                # store it as a string
                myacler.line = str(myint) 
            except Exception as e:
                logger.error(e)
                logger.error("Could not process row %s: %s" % (i, v[col]))
                sys.exit(1)


def get_elapsed_time_since(begin_time):
    """
    Take a starting time.time() param and return an elapsed time string
    """

    right_now = time.time()
    howlong = elapsed_time(int(right_now - begin_time))
    if '' == howlong.strip():
        howlong = '0s'
    return howlong


def build_rwfilter_working_file(start, end):
    """
    Query the repo using the acl address block set and generate
    a raw/rw working file.
    """

    # get wall clock start time
    t1 = time.time()

    # get the protocols that show up in the assessible ACL entries
    protocols = aclers_assess_protocols()

    cmd = "rwfilter --start=%s --end=%s --anyset=%s --proto=%s \
    --class=%s --type=%s --pass=%s" % (start, end, setfile, \
    protocols, options.silkclass, options.silktypes, rwfile)

    logger.info("repo pull rwfilter command: %s" % cmd)

    returncode = os.system(cmd)

    howlong = get_elapsed_time_since(t1)

    logger.info("Repo pull rwfilter took %s to run" % howlong)

    if returncode:
       logger.error("Repo pull rwfilter return code not zero: %s" % returncode)
       sys.exit(returncode)


def how_many_minutes(start_time):
    """
    Return the number of minutes from the provided
    start_time until now.
    """

    right_now = time.time()
    secs = int(start_time - right_now)
    if secs < 60:
        return 0
    else:
        return int(secs / 60)


def get_silk_file_record_count(filename):
    """Use rwfileinfo to get the record count"""

    myargs = ["rwfileinfo", "--fields=count-records", "--no-titles"]
    myargs.append("%s" % filename)

    try:
        # python 2.7+
        rec_count = int(subprocess.check_output(myargs))
        return rec_count
    except:
        # 2.6
        try:
            p = subprocess.Popen(myargs, stdout=subprocess.PIPE)
            output = p.communicate()[0]
            return int(output)
        except:
            logger.error("Can not determine record count for silk files")
            sys.exit(1)


def process_aclers_using_rwfilter_and_rwuniq(total_recs):
    """
    For each assessible ACL, pull a temp rwf file from the repo pull file
    using the ACL criteria and if there are records in it, use rwuniq
    to get the bytes, packets, and records. Do this in both criteria 
    directions, forward and reversed.
    """

    start_time = time.time()

    # don't assess non-assessible ACL's
    assessible_aclers = [a for a in aclers if a.assess()]

    num_assessible_acls = len(assessible_aclers)

    logger.info("Processing %d assessible ACL entries via rwfilter and rwuniq" % 
                num_assessible_acls)

    mycounter = 0

    for a in assessible_aclers:

        mycounter += 1

        a.num_days_checked += 1

        # Forward criteria

        unlink_file(tmprwfile)

        rwf = a.get_rwfilter_criteria()

        # add the working file locations
        rwf.append("--pass=%s" % tmprwfile)
        rwf.append("%s" % rwfile)

        logger.debug("Forward: %s" % a) 

        # use rwfilter criteria for this acl to read the working file
        # and create a temporary rwfilter file that rwuniq can read
        # No longer piping this straight to rwuniq so that rwuniq
        # does not get invoked with no-record cases.
        cmd = ' '.join(rwf)
        logger.debug("Forward: %s" % cmd)
        returncode = os.system(cmd)
        if returncode:
            logger.error("Forward rwfilter error code %s for %s" % (returncode, cmd))
            sys.exit(returncode)

        get_rwuniq_info(True, a) # True = forward

        # Reversed criteria

        unlink_file(tmprwfile)

        rwf = a.get_rwfilter_reversed_criteria()

        # add the working file locations
        rwf.append("--pass=%s" % tmprwfile)
        rwf.append("%s" % rwfile)

        logger.debug("Reversed: %s" % a) 
        cmd = ' '.join(rwf)
        logger.debug("Reversed: %s" % cmd)
        returncode = os.system(cmd)
        if returncode:
            logger.error("Reversed rwfilter error code %s for %s" % (returncode, cmd))
            sys.exit(returncode)

        get_rwuniq_info(False, a) # False = reversed

        if mycounter % 100 == 0:
            howlong = get_elapsed_time_since(start_time)
            logger.info("Compared %d ACL's both ways to %d flow records in %s" % (mycounter, total_recs, howlong))

    howlong = get_elapsed_time_since(start_time)
    logger.info("Compared %d ACL's both ways to %d flow records in %s" % (mycounter, total_recs, howlong))


def get_rwuniq_info(forward, myacler):
    """Use rwuniq to determine the number of bytes, packets, records for each ACL"""

    # standard rwuniq criteria used on each call
    rwu = ['rwuniq','--fields=type','--values=records,bytes,packets','--no-columns','--no-final-delimiter']
    rwu.append("%s" % tmprwfile)

    # if the temp rwf file has records, process them
    total_recs = get_silk_file_record_count(tmprwfile)

    if total_recs != 0:
        p = subprocess.Popen(rwu, stdout=subprocess.PIPE)
        output = p.communicate()[0]
        mylines = output.split("\n")

        for i in mylines:

            # push raw rwuniq output to debug
            if i.strip() != '':
                logger.debug(i)

            if i.startswith('type') or i.strip() == '':
                continue

            (mytype, myrecs, mybytes, mypackets) = i.split('|')

            if forward:
                # Increase the forward counts
                myacler.add_track(mytype, 'FR', int(myrecs))    # Forward Records
                myacler.add_track(mytype, 'FB', int(mybytes))   # Forward Bytes
                myacler.add_track(mytype, 'FP', int(mypackets)) # Forward Packets
            else:
                # Increase the reverse counts
                myacler.add_track(mytype, 'RR', int(myrecs))    # Reverse Records
                myacler.add_track(mytype, 'RB', int(mybytes))   # Reverse Bytes
                myacler.add_track(mytype, 'RP', int(mypackets)) # Reverse Packets


def write_csv_out_file(namepart):
    """
    Create a csv output file that contains that originial info but 
    includes the results of the flow checks.
    """

    # get the infile name without extension
    myname = os.path.splitext(os.path.basename(options.infile))[0] 
    csvoutfilename = "%s-%s-%s.csv" % (myname, namepart, mytime)
    csvoutfile = "%s/%s" % (options.outfiledir, csvoutfilename)
    logger.info("Writing CSV out to: %s" % csvoutfile)

    # load list with input csv info
    csvin = list()
    with open(options.infile, 'rb') as rf:
        reader = csv.reader(rf)
        for row in reader:
            csvin.append(row)
   
    # write the out file with csv in info and the results for each line
    with open(csvoutfile, 'wb') as wf:
        writer = csv.writer(wf)

        # iterate csvin and prefix the output with the flow results
        for i,v in enumerate(csvin):
            # get the AclerItem for this line
            myline = v[0].strip()
            a = [x for x in aclers if x.line == myline][0]
            # prefix is a list of the results data
            prefix = a.get_csv_out_prefix()
            # combine prefix with original minus the orig tracking
            # num row since it's on col one of prefix
            # this keeps tracking num at row one for any restarts
            writer.writerow(prefix + v[1:])


def build_file_names():
    """Create file names with date time component"""

    global mytime, rwfile, setfile, tmprwfile

    # get current datetime in clean format for file names
    # get the date and time with no seconds
    mytime = datetime.now().isoformat().split('.')[0]
    # remove the separators
    mytime = mytime.replace(':','').replace('-','')

    # working rwfilter pulled raw/rwf binary file
    rwfile = "%s/acler-%s.rwf" % (options.tmpfiledir, mytime)

    # silk set file
    setfile = "%s/acler-%s.set" % (options.tmpfiledir, mytime)

    # temp rwfilter pulled from working file
    tmprwfile = "%s/acler-%s-one-acl-check.rwf" % (options.tmpfiledir, mytime)


def aclers_assess_count():
    """Return the count of assessible items in the aclers list"""

    mycount = len([x for x in aclers if x.assess()])
    return mycount


def aclers_assess_protocols():
    """Return assessible protocols in the aclers list"""

    # go through a few girations to get numerically-sorted list
    proto_list = [int(x.protocol) for x in aclers if x.assess() and x.protocol]
    proto_list = sorted(list(set(proto_list)))
    protocols = ','.join(map(str, proto_list))
    return protocols
    

def main():

    global options, args

    (options, args) = option_and_logging_setup()

    build_file_names()
    aclfile_to_aclers(options.infile)

    # make sure there's something to work on
    numentries = aclers_assess_count()
    if numentries > 0:
        logger.info("Found %d assessible ACL lines in %s" % (numentries, options.infile))
        build_set()

        # first, let's just run the thing for one hour to eliminate 
        # any huge, constant talkers from the other pulls

        logger.info("First just checking for huge, constant talkers by checking one hour")
        start = "%s:00" % options.start
        build_rwfilter_working_file(start, start)
        total_recs = get_silk_file_record_count(rwfile)
        logger.info("SiLK working file has %d records" % total_recs)
        if total_recs >= 1:
            process_aclers_using_rwfilter_and_rwuniq(total_recs)
        mynamepart = "%s-00HourOnly" % options.start.replace('/','-')
        write_csv_out_file(mynamepart)
        unlink_working_files()

        # now run day by day
        DATE_FORMAT = "%Y/%m/%d"
        mystart = datetime.strptime(options.start, DATE_FORMAT)
        myend = datetime.strptime(options.end, DATE_FORMAT)
        delta = timedelta(days=1)
        
        while mystart <= myend:
            logger.info("Processing remaining ACL's against %s" % mystart.strftime("%Y-%m-%d"))
            numentries = aclers_assess_count()
            logger.info("Found %d assessible ACL lines" % numentries)
            if numentries > 0:
                build_set()
                start = mystart.strftime("%Y/%m/%d")
                build_rwfilter_working_file(start, start)
                total_recs = get_silk_file_record_count(rwfile)
                logger.info("SiLK working file has %d records" % total_recs)
                if total_recs >= 1:
                    process_aclers_using_rwfilter_and_rwuniq(total_recs)
                write_csv_out_file(mystart.strftime("%Y-%m-%d"))

            # move to the next day
            mystart += delta
            
            # clean up
            unlink_working_files()
        
    else:
        logger.error("Found no assessible ACL lines in %s" % options.infile)


def unlink_working_files():
    unlink_file(setfile)
    unlink_file(rwfile)
    unlink_file(tmprwfile)


def unlink_file(myfile):
    if os.path.exists(myfile):
        os.remove(myfile)


def option_and_logging_setup():
    """ process commandline options """
    usage = """usage: ./%prog [options]
    use -h for help / option descriptions 
    """

    global desired_types, logger

    parser = optparse.OptionParser(usage)

    parser.add_option("-i", "--in-file", dest="infile", help="""CSV file with non-extended Cisco ACL permit entries to check traffic against. First column must include integer line numbers for manual partial completion results reassembly in case the script gets killed and you have to rerun part of the days. Use csv_add_int.py if your CSV doesn't already have these. Use the -I option to specify the column with the ACL entries. Example /path/to/acker.py -i /home/username/my-acls.csv -I 3""")
    parser.add_option("-I", "--in-file-column", dest="infilecolumn", help="""Use this option to provide the one-based column number that contains the ACL entry""")
    parser.add_option("-o", "--out-file-dir", dest="outfiledir", help="""Directory where the output file should go. Defaults to home dir if not provided via CLI or env ACLER_OUTFILE_DIR. Example --out-file-dir=/somewhere/acl-stuff""")
    parser.add_option("-L", "--log-file-dir", dest="logfiledir", help="""Directory where the rotating log files should go. Defaults to home dir if not provided via CLI or env ACLER_LOGFILE_DIR. Example -L /path/to/acler/logs""")
    parser.add_option("-T", "--tmp-file-dir", dest="tmpfiledir", help="""Directory where the temp files should go. Must be provided via CLI or env ACLER_TMPFILE_DIR. Example --tmp-file-dir=/fastlargedrive/home/username""")
    parser.add_option("-s", "--start", dest="start", help="""Rwfilter start-date (no hour). Example --start=2015/07/23. Defaults to last 14 days.""")
    parser.add_option("-e", "--end", dest="end", help="""Rwfilter end-date (no hour). Example --end=2015/07/30. Defaults to last 14 days.""")
    parser.add_option("-c", "--class", dest="silkclass", help="""Rwfilter class. Example --class=<classname>. Defaults to environment variable ACLER_SILK_CLASS if present.""")
    parser.add_option("-t", "--types", dest="silktypes", help="""Rwfilter types. Example --types=in,out,inweb,outweb. Defaults to environment variable ACLER_SILK_TYPES if present. Check your silk.conf file for available types (usually at /data/silk.conf).""")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help="""Bumps the CLI log level from info to debug. Log file is always debug.""")

    (options, args) = parser.parse_args()

    # LOGFILE DIR
    if options.logfiledir:
        # if provided on the command line, use it
        pass
    elif os.environ.get('ACLER_LOGFILE_DIR'):
        # or if included via .bashrc use it
        options.logfiledir = os.environ['ACLER_LOGFILE_DIR']
    else:
        # or just use their home directory
        options.logfiledir = expanduser('~')

    # make sure the logfilepath exists
    if not os.path.exists(options.logfiledir):
        try:
            os.mkdir(options.logfiledir)
        except:
            print("Could not create log file dir: %s" % options.logfiledir)
            sys.exit(1)

    LOG_FILENAME = "%s/log-acler.log" % options.logfiledir

    ########### 
    ##  Logger set up

    # Set up local stdin and file log destinations
    logger = logging.getLogger(LOG_FILENAME)
    logger.setLevel(logging.DEBUG)
    # create file handler which logs even debug messages
    fh = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=1000000, backupCount=10)
    # We'll leave the info logged to file at debug and alter the command line based upon cli options
    fh.setLevel(logging.DEBUG)
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    if options.verbose:
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.INFO)
    # create formatters and add them to the handlers
    #chformatter = logging.Formatter('%(levelname)-8s %(message)s')
    fhformatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    #ch.setFormatter(chformatter)
    ch.setFormatter(fhformatter)
    fh.setFormatter(fhformatter)
    # add the handlers to logger
    logger.addHandler(ch)
    logger.addHandler(fh)

    ##
    ##########

    logger.debug("=================================================================================")
    logger.debug("========================== START OF NEW SCRIPT RUN ==============================")
    logger.debug("=================================================================================")

    logger.info("Check the log file at %s for debug-level logging info" % LOG_FILENAME)

    # for dev, used old LBNL reference silk data files
    # that need back dated query criteria. This is the lazy way
    # of calling my dev criteria each time.
    # https://tools.netsa.cert.org/silk/referencedata.html
    if os.environ.get('ACLER_DEV'):
        options.start = '2004/12/15'
        options.end   = '2005/01/30'

    if options.start:
        if not re.match('\d{4}/\d{2}/\d{2}', options.start):
            logger.error('-s parameter :%s: does not match required format: YYYY/MM/DD' % options.start)
            sys.exit(1)
    else:
        # Use 14 days ago
        weekago = date.today() - timedelta(days=14)
        options.start = weekago.isoformat().replace('-','/')

    if options.end:
        if not re.match('\d{4}/\d{2}/\d{2}', options.end):
            logger.error('-e parameter does not match required format: YYYY/MM/DD')
            sys.exit(1)
    else:
        # Use today
        options.end = date.today().isoformat().replace('-','/')

    # OUTFILE DIR
    if options.outfiledir:
        # if provided on the command line, use it
        pass
    elif os.environ.get('ACLER_OUTFILE_DIR'):
        # or if included via .bashrc use it
        options.outfiledir = os.environ['ACLER_OUTFILE_DIR']
    else:
        # or just use their home directory
        options.outfiledir = expanduser('~')

    # make sure the outfilepath exists
    if not os.path.exists(options.outfiledir):
        try:
            os.mkdir(options.outfiledir)
        except:
            logger.error("Could not create output file dir: %s" % options.outfiledir)
            sys.exit(1)

    # IN FILE
    if not options.infile:
        if os.environ.get('ACLER_DEV'):
            options.infile = 'example-acls.csv'
        else:
            logger.error("-i / --in-file required.")
            sys.exit(1)
    if not os.path.exists(options.infile) and not os.path.isfile(options.infile):
        logger.error("in-file %s does not exist or is not a regular file" % options.infile)
        sys.exit(1)

    # IN FILE COLUMN
    if options.infilecolumn:
        try:
            # make sure an integer was provided
            options.infilecolumn = int(options.infilecolumn)
        except:
            logger.error("In file column must be an integer")
            sys.exit(1)

        # make sure it's a positive integer
        if not (1 <= options.infilecolumn):
            logger.error("In file column must be 1 or higher")
            sys.exit(1)
    else:
        logger.error("In file column required. See option -I")
        sys.exit(1)

    # TMPFILE DIR
    if options.tmpfiledir:
        # if provided on the command line, use it
        pass
    elif os.environ.get('ACLER_TMPFILE_DIR'):
        # or if included via .bashrc use it
        options.tmpfiledir = os.environ['ACLER_TMPFILE_DIR']
    else:
        logger.error("Temp file dir required. See option -T")
        sys.exit(1)

    # make sure the tmpfilepath exists
    if not os.path.exists(options.tmpfiledir):
        try:
            os.mkdir(options.tmpfiledir)
        except:
            logger.error("Could not create tmp file dir: %s" % options.tmpfiledir)
            sys.exit(1)

    # class
    if not options.silkclass:
        if os.environ.get('ACLER_SILK_CLASS'):
            options.silkclass = os.environ['ACLER_SILK_CLASS']
        else:
            logger.error("Options -c required")
            sys.exit(1)
    # limit to certain characters since we don't know what valid classes might be
    for i in options.silkclass:
        if not re.match('[A-Za-z0-9-]', i):
            logger.error("Invalid character '%s' found in SiLK class, must be A-Za-z0-9-" % i)
            sys.exit(1)
        
    # types
    if not options.silktypes:
        if os.environ.get('ACLER_SILK_TYPES'):
            options.silktypes = os.environ['ACLER_SILK_TYPES']
        else:
            logger.error("Options -t required")
            sys.exit(1)
    # limit to certain characters since we don't know what valid types might be
    # commas are allowed since this can be a list of types
    for i in options.silktypes:
        if not re.match('[A-Za-z0-9-,]', i):
            logger.error("Invalid character '%s' found in SiLK types, must be A-Za-z0-9-" % i)
            sys.exit(1)

    # convert text based info to list
    if ',' in options.silktypes:
        desired_types = [x.strip() for x in options.silktypes.split(',')]
    else:
        desired_types.append(options.silktypes.strip())

    return (options, args)

if __name__ == '__main__':
    main()
