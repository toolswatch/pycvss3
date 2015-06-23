#!/usr/bin/env python
# Copyright (C) 2015 ToolsWatch.org
# This file is part of vFeed Aggregated Vulnerability Database Community

from lib.pycvss3 import CVSS3

print "Example 1"
cvss3_vector = "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:L/MUI:N/MS:C/MC:H/MI:H/MA:H"
cvss3 = CVSS3(cvss3_vector)
cvss_base_score_risk = cvss3.cvss_base_score()
cvss_temporal_score_risk = cvss3.cvss_temporal_score()
print "CVSS v3 vector:", cvss3_vector
print "\tCVSS v3 Base Score and Risk Level", cvss_base_score_risk
print "\tCVSS v3 Temporal Score:", cvss_temporal_score_risk

print ""
print "Example 2"
cvss3_vector = "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:X/RC:X"
cvss3 = CVSS3(cvss3_vector)
cvss_base_score_risk = cvss3.cvss_base_score()
cvss_temporal_score_risk = cvss3.cvss_temporal_score()
print "CVSS v3 vector:", cvss3_vector
print "\tCVSS v3 Base Score and Risk Level", cvss_base_score_risk
print "\tCVSS v3 Temporal Score:", cvss_temporal_score_risk

print ""
print "Example 3"
cvss3_vector = "AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N/E:X/RL:X/RC:X"
cvss3 = CVSS3(cvss3_vector)
cvss_base_score_risk = cvss3.cvss_base_score()
cvss_temporal_score_risk = cvss3.cvss_temporal_score()
print "CVSS v3 vector:", cvss3_vector
print "\tCVSS v3 Base Score and Risk Level", cvss_base_score_risk
print "\tCVSS v3 Temporal Score:", cvss_temporal_score_risk

print ""
print "Example 4"
cvss3_vector = "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:L/MUI:N/MS:C/MC:H/MI:H/MA:H"
cvss3 = CVSS3(cvss3_vector)
cvss_base_score_risk = cvss3.cvss_base_score()
cvss_temporal_score_risk = cvss3.cvss_temporal_score()
cvss_environmental_score_risk = cvss3.cvss_environmental_score()
print "CVSS v3 vector:", cvss3_vector
print "\tCVSS v3 Base Score:", cvss_base_score_risk
print "\tCVSS v3 Temporal Score:", cvss_temporal_score_risk
print "\tCVSS 3 Environmental Score:", cvss_environmental_score_risk

print ""
print "Example 5"
cvss3_vector = "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:H/MUI:N/MS:U/MC:L/MI:H/MA:L"
cvss3 = CVSS3(cvss3_vector)
cvss_base_score_risk = cvss3.cvss_base_score()
cvss_temporal_score_risk = cvss3.cvss_temporal_score()
cvss_environmental_score_risk = cvss3.cvss_environmental_score()
print "CVSS v3 vector:", cvss3_vector
print "\tCVSS v3 Base Score:", cvss_base_score_risk
print "\tCVSS v3 Temporal Score:", cvss_temporal_score_risk
print "\tCVSS 3 Environmental Score:", cvss_environmental_score_risk

print ""
print "Example 6"
cvss3_vector = "AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:P/RL:T/RC:R/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H"
cvss3 = CVSS3(cvss3_vector)
cvss_base_score_risk = cvss3.cvss_base_score()
cvss_temporal_score_risk = cvss3.cvss_temporal_score()
cvss_environmental_score_risk = cvss3.cvss_environmental_score()
print "CVSS v3 vector:", cvss3_vector
print "\tCVSS v3 Base Score:", cvss_base_score_risk
print "\tCVSS v3 Temporal Score:", cvss_temporal_score_risk
print "\tCVSS 3 Environmental Score:", cvss_environmental_score_risk

print ""
print "Example 7"
cvss3_vector = "AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:P/RL:T/RC:R/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:U/MC:N/MI:N/MA:N"
cvss3 = CVSS3(cvss3_vector)
cvss_base_score_risk = cvss3.cvss_base_score()
cvss_temporal_score_risk = cvss3.cvss_temporal_score()
cvss_environmental_score_risk = cvss3.cvss_environmental_score()
print "CVSS v3 vector:", cvss3_vector
print "\tCVSS v3 Base Score:", cvss_base_score_risk
print "\tCVSS v3 Temporal Score:", cvss_temporal_score_risk
print "\tCVSS 3 Environmental Score:", cvss_environmental_score_risk

print ""
print "Example 8 - Printing only scores"
cvss3_vector = "AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/E:H/RL:W/RC:U/CR:H/IR:H/AR:M/MAV:L/MAC:L/MPR:H/MUI:N/MS:C/MC:N/MI:H/MA:L"
cvss3 = CVSS3(cvss3_vector)
(cvss_base_score,cvss_base_risk) = cvss3.cvss_base_score()
(cvss_temporal_score,cvss_temporal_risk) = cvss3.cvss_temporal_score()
(cvss_environmental_score,cvss_environmental_risk)= cvss3.cvss_environmental_score()
print "CVSS v3 vector:", cvss3_vector
print "\tCVSS v3 Base Score:", cvss_base_score
print "\tCVSS v3 Temporal Score:", cvss_temporal_score
print "\tCVSS 3 Environmental Score:", cvss_environmental_score

print ""
print "Example 9 - Printing only ratings"
cvss3_vector = "AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/E:H/RL:W/RC:U/CR:H/IR:H/AR:M/MAV:L/MAC:L/MPR:H/MUI:N/MS:C/MC:N/MI:H/MA:L"
cvss3 = CVSS3(cvss3_vector)
(cvss_base_score,cvss_base_risk) = cvss3.cvss_base_score()
(cvss_temporal_score,cvss_temporal_risk) = cvss3.cvss_temporal_score()
(cvss_environmental_score,cvss_environmental_risk)= cvss3.cvss_environmental_score()
print "CVSS v3 vector:", cvss3_vector
print "\tCVSS v3 Base rating:", cvss_base_risk
print "\tCVSS v3 Temporal rating:", cvss_temporal_risk
print "\tCVSS 3 Environmental rating:", cvss_environmental_risk
