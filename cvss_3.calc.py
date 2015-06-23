#!/usr/bin/env python
# Copyright (C) 2015 ToolsWatch.org
# This file is part of vFeed Aggregated Vulnerability Database Community
__version__ = 0.3
__author__ = "NJ OUCHN (@toolswatch)"

import argparse
from lib.pycvss3 import CVSS3

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--version", action="version",
                        version="pycvss3 - The CVSS v3 Python Calculator version {0} by {1} ".format(__version__, __author__))
    parser.add_argument("--vector", metavar="Vector mode", type=str,
                        help="Paste the CVSS v3 vector string (without CVSS:3.0/) ")
    args = parser.parse_args()

    if args.vector:
        cvss3 = CVSS3(args.vector)
        (cvss_base_value, cvss_base_risk_level) = cvss3.cvss_base_score()
        (cvss_temporal_value, cvss_temporal_risk_level) = cvss3.cvss_temporal_score()
        (cvss_environmental_value, cvss_environmental_risk_level) = cvss3.cvss_environmental_score()

        print "CVSS v3 vector:", args.vector
        print "\tCVSS 3 Base Score: %s | Rating : %s" % (cvss_base_value, cvss_base_risk_level)
        print "\tCVSS 3 Temporal Score: %s | Rating : %s" % (cvss_temporal_value, cvss_temporal_risk_level)
        print "\tCVSS 3 Environmental Score: %s | Rating : %s" % (
            cvss_environmental_value, cvss_environmental_risk_level)
