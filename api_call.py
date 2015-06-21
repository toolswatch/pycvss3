#!/usr/bin/env python
# Copyright (C) 2015 ToolsWatch.org
# This file is part of vFeed Aggregated Vulnerability Database Community

from lib.pycvss3 import Vector

cvss3_vector = "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:L/MUI:N/MS:C/MC:H/MI:H/MA:H"
cvss3 = Vector(cvss3_vector)
cvss_base_value = cvss3.cvss_base_score()
cvss_temporal_value = cvss3.cvss_temporal_score()

print "CVSS v3 vector:", cvss3_vector
print "\tCVSS v3 Base Score:", cvss_base_value
print "\tCVSS v3 Temporal Score:", cvss_temporal_value

cvss3_vector = "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:X/RC:X"
cvss3 = Vector(cvss3_vector)
cvss_base_value = cvss3.cvss_base_score()
cvss_temporal_value = cvss3.cvss_temporal_score()

print ""
print "CVSS v3 vector:", cvss3_vector
print "\tCVSS v3 Base Score:", cvss_base_value
print "\tCVSS v3 Temporal Score:", cvss_temporal_value

cvss3_vector = "AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N/E:X/RL:X/RC:X"
cvss3 = Vector(cvss3_vector)
cvss_base_value = cvss3.cvss_base_score()
cvss_temporal_value = cvss3.cvss_temporal_score()

print ""
print "CVSS v3 vector:", cvss3_vector
print "\tCVSS v3 Base Score:", cvss_base_value
print "\tCVSS v3 Temporal Score:", cvss_temporal_value

cvss3_vector = "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:L/MUI:N/MS:C/MC:H/MI:H/MA:H"
cvss3 = Vector(cvss3_vector)
cvss_base_value = cvss3.cvss_base_score()
cvss_temporal_value = cvss3.cvss_temporal_score()
cvss_environmental_value = cvss3.cvss_environmental_score()

print ""
print "CVSS v3 vector:", cvss3_vector
print "\tCVSS v3 Base Score:", cvss_base_value
print "\tCVSS v3 Temporal Score:", cvss_temporal_value
print "\tCVSS 3 Environmental Score:", cvss_environmental_value

cvss3_vector = "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:H/MUI:N/MS:U/MC:L/MI:H/MA:L"
cvss3 = Vector(cvss3_vector)
cvss_base_value = cvss3.cvss_base_score()
cvss_temporal_value = cvss3.cvss_temporal_score()
cvss_environmental_value = cvss3.cvss_environmental_score()

print ""
print "CVSS v3 vector:", cvss3_vector
print "\tCVSS v3 Base Score:", cvss_base_value
print "\tCVSS v3 Temporal Score:", cvss_temporal_value
print "\tCVSS 3 Environmental Score:", cvss_environmental_value
