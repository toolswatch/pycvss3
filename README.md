# pycvss3 - Python API for the CVSS v3

First.org made available the version 3 of the Common Vulnerability Scoring System (CVSS). The new system is the latest update of the universal open and standardized method for rating IT vulnerabilities and determining the urgency of response. 
The updated version includes enhancements such as: the promotion of consistency in scoring, the replacement of Scoring Tips in order to more clearly guide end users of CVSS, and consideration of the system in order to make it more applicable to modern concerns. More information on the standard is available at https://www.first.org/cvss.

pycvss3 is Python library calculator for the newest CVSS v3 and can be invoked from scripts as API or directly from command line.  

How to ?
==============

Run `cvss_3.calc.py` it's self-explanatory. The only input is the CVSS v3 vectors.

Or edit the `api_call.py` to see how to leverage the class from your scripts.

v0.1
---------
* Initial release with the ability to calculatec the Base and Temporal scores in compliance with the CVSS v3.0 specifications  (https://www.first.org/cvss/specification-document)
The environmental score will be added later despite the fact the formula is in the code and working great. 
* Added api_call.py to demonstrate how to invoke the class.
* Added the cvss_3.calc.py command line that accepts the CVSS v3.0 vector as input.
