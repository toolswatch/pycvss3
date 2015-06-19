# pycvss3
Python API for the CVSS v3
This is the first python API for the Common Vulnerability Scoring System v3.0.

This beta release calculates the Base and Temporal scores in compliance with CVSS v3.0 specs >> https://www.first.org/cvss/specification-document
The environmental score will be added later despite the fact the formula is in the code and working great. 

The api_call.py shows how the pycvss3 could be leveraged as API.
cvss_3.calc.py is a CLI and accepts the CVSS v3.0 vector as input.
