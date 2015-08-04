# acler

Acler is a Python 2.6+ script (and local modules) to read a file of non-extended Cisco ACL permit entries and return a results file with info about whether/not netflow records associated with the entries had traffic or not.

The script parses the Cisco ACL entries, creates a SiLK set file, pulls a SiLK working file into a temp folder based on the set file, reads the working file and runs the ACL criteria against each record of the working file, both forward (the way the ACL was written) and reversed (with the criteria flipped), keeping track of forward and reverse bytes, packets, and records. Upon output, it also includes the average bytes/packet for forward and reversed traffic.

The idea is to use this script to help inform security policy folks during routine ACL cleanup cycles. If there is traffic, then perhaps the ACL is still needed, but if not, perhaps it's OBE (overcome by events).

The output/results file includes the original line number from the ACL file, the ACL entry, and result information.

See acler-help.txt for the help info, or run python ./acler.py -h

SiLK: https://tools.netsa.cert.org/silk/index.html
