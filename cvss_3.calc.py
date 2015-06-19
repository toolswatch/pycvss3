#!/usr/bin/env python
# Copyright (C) 2015 ToolsWatch.org
# This file is part of vFeed Aggregated Vulnerability Database Community
__version__ = 0.1
__author__ = "NJ OUCHN @toolswatch"

import argparse
from lib.pycvss3 import Vector

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--version", action="version",
                        version="You are using pycvss3 {0} by {1} ".format(__version__, __author__))
    parser.add_argument("--vector", metavar="Vector mode", type=str, help="Paste the CVSS v3 vector string (without CVSS:3.0/) ")
    args = parser.parse_args()

    if args.vector:
        vector = Vector(args.vector)
        cvss_base_value = vector.cvss_base_score()
        cvss_temporal_value = vector.cvss_temporal_score()

        print "\tCVSS v3 Base Score:", cvss_base_value
        print "\tCVSS v3 Temporal Score:", cvss_temporal_value

