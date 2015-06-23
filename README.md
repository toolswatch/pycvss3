# pycvss3 - Python API for the CVSS v3

First.org made available the version 3 of the Common Vulnerability Scoring System (CVSS). The new system is the latest update of the universal open and standardized method for rating IT vulnerabilities and determining the urgency of response. 
The updated version includes enhancements such as: the promotion of consistency in scoring, the replacement of Scoring Tips in order to more clearly guide end users of CVSS, and consideration of the system in order to make it more applicable to modern concerns. More information on the standard is available at https://www.first.org/cvss.

pycvss3 is Python library calculator for the newest CVSS v3 and can be invoked from scripts as API or directly from command line. The API and CLI can both display the score alongside the Qualitative Rating Scale




Basic usage
==============
<pre><code> 
./cvss_3.calc.py --vector AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:P/RL:T/RC:R/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:U/MC:N/MI:N/MA:N
CVSS v3 vector: AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N/E:P/RL:T/RC:R/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:U/MC:N/MI:N/MA:N
        CVSS 3 Base Score: 0.0 --> Risk Level: None
        CVSS 3 Temporal Score: 0.0 --> Risk Level: None
        CVSS 3 Environmental Score: 0.0 --> Risk Level: None

./cvss_3.calc.py --vector AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/E:H/RL:W/RC:U/CR:H/IR:H/AR:M/MAV:L/MAC:L/MPR:H/MUI:N/MS:C/MC:N/MI:H/MA:L
CVSS v3 vector: AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:H/E:H/RL:W/RC:U/CR:H/IR:H/AR:M/MAV:L/MAC:L/MPR:H/MUI:N/MS:C/MC:N/MI:H/MA:L
        CVSS 3 Base Score: 5.8 | Rating : Medium
        CVSS 3 Temporal Score: 5.2 | Rating : Medium
        CVSS 3 Environmental Score: 7.4 | Rating : High
</code></pre>

Calling the API
==============

Edit the `api_call.py` to see how to leverage the class from your scripts.

To do
==============

* Clean and optimize the pycvss3 code

v0.3
---------
* Added the support to the Qualitative Rating scale as defined in the CVSS v3 User Guide >> https://www.first.org/cvss/user-guide
* Renamed and refactored the Vector Class to CVSS3
* Update the pycvss3.py to reflect the change.

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
