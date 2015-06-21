# pycvss3 - Python API for the CVSS v3

First.org made available the version 3 of the Common Vulnerability Scoring System (CVSS). The new system is the latest update of the universal open and standardized method for rating IT vulnerabilities and determining the urgency of response. 
The updated version includes enhancements such as: the promotion of consistency in scoring, the replacement of Scoring Tips in order to more clearly guide end users of CVSS, and consideration of the system in order to make it more applicable to modern concerns. More information on the standard is available at https://www.first.org/cvss.

pycvss3 is Python library calculator for the newest CVSS v3 and can be invoked from scripts as API or directly from command line.  

Basic usage
==============
<pre><code> 

./cvss_3.calc.py --vector AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:H/MUI:N/MS:U/MC:L/MI:H/MA:L 

CVSS v3 vector: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:H/MUI:N/MS:U/MC:L/MI:H/MA:L
        --> CVSS 3 Base Score: 10.0
        --> CVSS 3 Temporal Score: 10.0
        --> CVSS 3 Environmental Score: 7.2

</code></pre>

Calling the API
==============

Edit the `api_call.py` to see how to leverage the class from your scripts.

To do
==============

* Clean and dptimize the pycvss3 code

v0.2
---------
* Added support to Environmental score. 
* Fixed few calculation bugs in pycvss.py class
* Fixed the non_defined valued in  metrics.py class

v0.1
---------
* Initial release with the ability to calculatec the Base and Temporal scores in compliance with the CVSS v3.0 specifications  (https://www.first.org/cvss/specification-document)
The environmental score will be added later despite the fact the formula is in the code and working great. 
* Added api_call.py to demonstrate how to invoke the class.
* Added the cvss_3.calc.py command line that accepts the CVSS v3.0 vector as input.
