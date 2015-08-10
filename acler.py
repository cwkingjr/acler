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
import sys
import time

# global vars
aclers = list() # list of AclerItem objects
setfile = None # silk set file
mytime = None # clean datetime info for inclusion in file names
rwfile = None # rwf working file
desired_types = list() # silk types to track
options = None # option parsing
args = None # option parsing
logger = None # logging handler


def get_initial_pull_silk_set():
    """
    Build a silk set of the smallest ip block (sip or dip) from
    each parsed acl record. This will be used by the initial 
    rwfilter pull to build a working file of the traffic we
    need to analyze. This is instead of hitting the repo 
    numerous times.
    """

    global setfile, options

    # gather up the smallest ip block from each acl
    blocks = list()
    for i in aclers:
        if i.assess:
            a = i.smallest_ip_block()
            blocks.append(a)

    # build a set file
    myset = IPSet(blocks)
    logger.info("Saving ACL SiLK set file at: %s" % setfile)
    myset.save(setfile)


def set_assess_flag():
    """
    Iterate aclers and set the assess flag on items that can
    be assessed against the rwfile.
    """

    for i in aclers:
        # if the acl was parsed and at least one side has an address
        if i.parsed:
            if i.sip is not None or i.dip is not None:
                i.assess = True
            else:
                i.error = 'Not assessed due to no sip or dip block'


def aclfile_to_aclers(aclfilename):
    """
    Read the lines in the acl file and convert each line to an
    AclerItem, adding each AclerItem to the aclers list. If an
    in file column is provided, process the file as a CSV.
    """

    # CSV
    if options.infilecolumn:

        logger.info("Processing ACL file %s as CSV file using column %d" % (aclfilename, options.infilecolumn))

        with open(aclfilename, 'rb') as f:

            reader = csv.reader(f) 

            # enumerate provides index and value
            for i,v in enumerate(reader):
                i = i + 1 # make one based

                # make sure there are enough columns in the row
                if options.infilecolumn > len(v):
                    msg = "CSV line %d does not have enough sections to process col %d: %s" % (i, options.infilecolumn, v)
                    logger.error(msg)
                    myname = ' '.join(v)
                    myacler = AclerItem(myname)
                    myacler.line = i
                    myacler.error = msg
                    aclers.append(myacler)
                    continue

                # convert to zero based for the list
                col = options.infilecolumn - 1

                try:
                    myacler = parse_cisco(v[col])
                    myacler.line = i
                    aclers.append(myacler)
                except Exception as e:
                    logger.error(e)
                    logger.error("Could not process line %s: %s" % (i, v[col]))
                    sys.exit(1)

    # Not CSV
    else:

        logger.info("Processing ACL file %s as text file" % aclfilename)

        with open(aclfilename) as f:

            # enumerate provides index and value
            for i,v in enumerate(f.readlines()):
                i = i + 1 # make one based
                try:
                    myacler = parse_cisco(v)
                    myacler.line = i
                    aclers.append(myacler)
                except Exception as e:
                    logger.error(e)
                    logger.error("Could not process line %s: %s" % (i, v))
                    sys.exit(1)


def build_rwfilter_working_file():
    """
    Query the repo using the acl address block set and generate
    a raw/rw working file.
    """

    global options

    # get wall clock start time
    t1 = time.time()

    rwfiltercommand = "rwfilter --start=%s --end=%s --anyset=%s --proto=1- \
    --class=%s --type=%s --pass=%s" % (options.start, options.end, setfile, \
    options.silkclass, options.silktypes, rwfile)

    logger.info("rwfilter command: %s" % rwfiltercommand)

    returncode = os.system(rwfiltercommand)

    # get wall clock end time
    t2 = time.time()
    howlong = elapsed_time(int(t2 - t1))

    # on at least the dev system, this can be so fast it doesn't 
    # generate a time difference
    if '' == howlong.strip():
        howlong = '0s'

    logger.info("rwfilter took %s to run" % howlong)

    if returncode:
       logger.error("rwfilter return code not zero: %s" % returncode)
       sys.exit(returncode)
    else:
       logger.info("rwfilter completed successfully")


def process_aclers_against_rwfile():
    """
    Read the fwfile and load assessable acler items using
    silk criteria.
    """

    global desired_types

    logger.info("Comparing ACL criteria to SiLK working file: %s" % rwfile)

    infile = silkfile_open(rwfile, READ)

    for rec in infile:

        # only track requested silk types
        if not rec.typename in desired_types:
            logger.debug("Skipping type: '%s' not in %s" % (rec.typename, desired_types))
            continue

        for i in aclers:

            if i.assess:

                # forward query
                q = i.get_silk_criteria()
                if eval(q):
                    i.add_track(rec.typename, 'FR', 1)
                    i.add_track(rec.typename, 'FB', rec.bytes)
                    i.add_track(rec.typename, 'FP', rec.packets)

                # reversed query
                q = i.get_silk_reversed_criteria()
                if eval(q):
                    i.add_track(rec.typename, 'RR', 1)
                    i.add_track(rec.typename, 'RB', rec.bytes)
                    i.add_track(rec.typename, 'RP', rec.packets)


def write_result_file():
    """
    Create an output file with each acl line, line number, 
    and result info.
    """

    global options

    outfilename = "out-acler-%s.txt" % mytime
    outfile = "%s/%s" % (options.outfiledir, outfilename)

    with open(outfile, 'w') as f:

        logger.info("Writing output file: %s" % outfile)

        for i in aclers:
            # entries with traffic
            if i.has_records():
                f.write(i.dump_traffic())
            # entries with no traffic
            elif i.assess and not i.has_records():
                f.write(i.dump_no_traffic())
            elif not i.assess:
                f.write(i.dump_no_assess())


def build_file_names():
    """Create file names with date time component"""

    global rwfile, setfile, mytime, options

    # get current datetime in clean format for file names
    # get the date and time with no seconds
    mytime = datetime.now().isoformat().split('.')[0]
    # remove the separators
    mytime = mytime.replace(':','').replace('-','')

    # working rwfilter pulled raw/rwf binary file
    rwfile = "%s/acler-%s.rwf" % (options.tmpfiledir, mytime)

    # silk set file
    setfile = "%s/acler-%s.set" % (options.tmpfiledir, mytime)


def aclers_assess_count():
    """Return the count of assessible items in the aclers list"""

    global aclers

    mycount = len([x for x in aclers if x.assess])
    return mycount


def main():

    global aclers, rwfile, setfile, mytime, options, args

    (options, args) = option_and_logging_setup()

    build_file_names()
    aclfile_to_aclers(options.infile)
    set_assess_flag()

    # make sure there's something to work on
    numentries = aclers_assess_count()
    if numentries > 0:
        logger.info("Found %d assessible ACL lines in %s" % (numentries, options.infile))
        get_initial_pull_silk_set()
        build_rwfilter_working_file()
        process_aclers_against_rwfile()
        write_result_file()
    else:
        logger.error("Found no assessible ACL lines in %s" % options.infile)
        write_result_file()

    if not options.nodeltmp:
        if os.path.exists(setfile):
            logger.info("Deleting the set file")
            os.remove(setfile)
        if os.path.exists(rwfile):
            logger.info("Deleting the rw working file")
            os.remove(rwfile)
    else:
        logger.info("Don't forget to prune your set/rw files manually")


def option_and_logging_setup():
    """ process commandline options """
    usage = """usage: ./%prog [options]
    use -h for help / option descriptions 
    """

    global desired_types, logger

    parser = optparse.OptionParser(usage)

    parser.add_option("-i", "--in-file", dest="infile", help="""Non-extended Cisco ACL permit file to check traffic against. Example -i /home/username/my-acls.txt""")
    parser.add_option("-I", "--in-file-column", dest="infilecolumn", help="""If the in file is a CSV, use this option to provide the one-based column that contains the ACL entry""")
    parser.add_option("-o", "--out-file-dir", dest="outfiledir", help="""Directory where the output file should go. Defaults to home dir if not provided via CLI or env ACLER_OUTFILE_DIR. Example --out-file-dir=/somewhere/acl-stuff""")
    parser.add_option("-L", "--log-file-dir", dest="logfiledir", help="""Directory where the rotating log files should go. Defaults to home dir if not provided via CLI or env ACLER_LOGFILE_DIR. Example -L /path/to/acler/logs""")
    parser.add_option("-T", "--tmp-file-dir", dest="tmpfiledir", help="""Directory where the temp files should go. Defaults to home dir if not provided via CLI or env ACLER_TMPFILE_DIR. Example --tmp-file-dir=/fastdrive/home/username""")
    parser.add_option("-n", "--no-del", action="store_true", dest="nodeltmp", help="""Do not delete temp files""")
    parser.add_option("-s", "--start", dest="start", help="""Rwfilter start-date (no hour). Example --start=2015/07/23. Defaults to last seven days.""")
    parser.add_option("-e", "--end", dest="end", help="""Rwfilter end-date (no hour). Example --end=2015/07/30. Defaults to last seven days.""")
    parser.add_option("-c", "--class", dest="silkclass", help="""Rwfilter class. Example --class=<classname>. Defaults to environment variable ACLER_SILK_CLASS if present.""")
    parser.add_option("-t", "--types", dest="silktypes", help="""Rwfilter types. Example --types=in,out,inweb,outweb. Defaults to environment variable ACLER_SILK_TYPES if present. Check your silk.conf file for available types (usually at /data/silk.conf).""")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help="""Bumps log level from info to debug""")

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
    # you can use the same one but I didn't want the datetime on the console
    chformatter = logging.Formatter('%(levelname)-8s %(message)s')
    fhformatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(chformatter)
    fh.setFormatter(fhformatter)
    # add the handlers to logger
    logger.addHandler(ch)
    logger.addHandler(fh)

    ##
    ##########

    logger.debug("=================================================================================")
    logger.debug("========================== STARTING NEW SCRIPT RUN ==============================")
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
        # Use seven days ago
        weekago = date.today() - timedelta(days=7)
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
            options.infile = 'example-acls.txt'
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

    # TMPFILE DIR
    if options.tmpfiledir:
        # if provided on the command line, use it
        pass
    elif os.environ.get('ACLER_TMPFILE_DIR'):
        # or if included via .bashrc use it
        options.tmpfiledir = os.environ['ACLER_TMPFILE_DIR']
    else:
        # or just use their home directory
        options.tmpfiledir = expanduser('~')

    # make sure the outfilepath exists
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
