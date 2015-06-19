#!/usr/bin/env python
# Copyright (C) 2015 ToolsWatch.org
# This file is part of vFeed Aggregated Vulnerability Database Community

from metrics import Metrics
from formulas import *


class Vector(object):
    def __init__(self, vector):
        self.vectors = vector.split('/')

    def get_vectors(self):
        """ Extract metrics from CVSS v3 vector format
        :return: Metrics values
        """
        for self.vector in self.vectors:
            self.splitted = self.vector[0:].split(':')
            self.metric_vector = self.splitted[0]
            self.metric_value = self.splitted[1]

            if self.metric_vector == "AV":
                if self.metric_value == "N" or self.metric_value == "network":
                    self.attack_vector_value = Metrics.attack_vector.network
                if self.metric_value == "A" or self.metric_value == "adjacent_network":
                    self.attack_vector_value = Metrics.attack_vector.adjacent_network
                if self.metric_value == "L" or self.metric_value == "local":
                    self.attack_vector_value = Metrics.attack_vector.local
                if self.metric_value == "P" or self.metric_value == "physical":
                    self.attack_vector_value = Metrics.attack_vector.physical

            if self.metric_vector == "AC":
                if self.metric_value == "L" or self.metric_value == "low":
                    self.attack_complexity_value = Metrics.attack_complexity.low
                if self.metric_value == "H" or self.metric_value == "high":
                    self.attack_complexity_value = Metrics.attack_complexity.high

            if self.metric_vector == "UI":
                if self.metric_value == "N" or self.metric_value == "none":
                    self.user_interaction_value = Metrics.user_interaction.none
                if self.metric_value == "R" or self.metric_value == "required":
                    self.user_interaction_value = Metrics.user_interaction.required

            # Assigning the appropriate value to PR depending on the Scope. See the formula.
            if self.metric_vector == "S":
                self.scope_value = self.metric_value
                # getting the value of PR vector from the original splitted vectors
                self.splitted_2 = self.vectors[2:3][0].split(':')
                self.metric_vector = self.splitted_2[0]
                self.metric_value = self.splitted_2[1]

                if self.scope_value == "C" or self.scope_value == "changed":
                    self.scope_value = "changed"
                    if self.metric_vector == "PR":
                        if self.metric_value == "N" or self.metric_value == "none":
                            self.privileges_required_value = Metrics.privileges_required_changed.none
                        if self.metric_value == "L" or self.metric_value == "low":
                            self.privileges_required_value = Metrics.privileges_required_changed.low
                        if self.metric_value == "H" or self.metric_value == "high":
                            self.privileges_required_value = Metrics.privileges_required_changed.high
                else:
                    self.scope_value = "unchanged"
                    if self.metric_value == "N" or self.metric_value == "none":
                        self.privileges_required_value = Metrics.privileges_required.none
                    elif self.metric_value == "L" or self.metric_value == "low":
                        self.privileges_required_value = Metrics.privileges_required.low
                    elif self.metric_value == "H" or self.metric_value == "high":
                        self.privileges_required_value = Metrics.privileges_required.high
                    else:
                        raise Exception, "(PR) Privileges Required metric is not correct"

            if self.metric_vector == "C":
                if self.metric_value == "L" or self.metric_value == "low":
                    self.confidentiality_value = Metrics.cia_impact.low
                elif self.metric_value == "H" or self.metric_value == "high":
                    self.confidentiality_value = Metrics.cia_impact.high
                elif self.metric_value == "N" or self.metric_value == "none":
                    self.confidentiality_value = Metrics.cia_impact.none
                else:
                    raise Exception, "(C) Confidentiality metric is not correct"

            if self.metric_vector == "I":
                if self.metric_value == "L" or self.metric_value == "low":
                    self.integrity_value = Metrics.cia_impact.low
                elif self.metric_value == "H" or self.metric_value == "high":
                    self.integrity_value = Metrics.cia_impact.high
                elif self.metric_value == "N" or self.metric_value == "none":
                    self.integrity_value = Metrics.cia_impact.none
                else:
                    raise Exception, "(I) Integrity metric is not correct"

            if self.metric_vector == "A":
                if self.metric_value == "L" or self.metric_value == "low":
                    self.availability_value = Metrics.cia_impact.low
                elif self.metric_value == "H" or self.metric_value == "high":
                    self.availability_value = Metrics.cia_impact.high
                elif self.metric_value == "N" or self.metric_value == "none":
                    self.availability_value = Metrics.cia_impact.none
                else:
                    raise Exception, "(A) Availability metric is not correct"

            if self.metric_vector == "E":
                if self.metric_value == "X" or self.metric_value == "not_defined" or self.metric_value == "not defined":
                    self.exploit_code_maturity_value = Metrics.exploit_code_maturity.not_defined
                elif self.metric_value == "H" or self.metric_value == "high":
                    self.exploit_code_maturity_value = Metrics.exploit_code_maturity.high
                elif self.metric_value == "F" or self.metric_value == "functional":
                    self.exploit_code_maturity_value = Metrics.exploit_code_maturity.functional
                elif self.metric_value == "P" or self.metric_value == "proof_of_concept" or self.metric_value == "proof of concept":
                    self.exploit_code_maturity_value = Metrics.exploit_code_maturity.proof_of_concept
                elif self.metric_value == "U" or self.metric_value == "unproven":
                    self.exploit_code_maturity_value = Metrics.exploit_code_maturity.unproven

            if self.metric_vector == "RL":
                if self.metric_value == "X" or self.metric_value == "not_defined" or self.metric_value == "not defined":
                    self.remediation_level_value = Metrics.remediation_level.not_defined
                elif self.metric_value == "U" or self.metric_value == "unavailable":
                    self.remediation_level_value = Metrics.remediation_level.unavailable
                elif self.metric_value == "W" or self.metric_value == "workaround":
                    self.remediation_level_value = Metrics.remediation_level.workaround
                elif self.metric_value == "T" or self.metric_value == "temporary_fix" or self.metric_value == "temporary fix":
                    self.remediation_level_value = Metrics.remediation_level.temporary_fix
                elif self.metric_value == "O" or self.metric_value == "official_fix" or self.metric_value == "official fix":
                    self.remediation_level_value = Metrics.remediation_level.official_fix

            if self.metric_vector == "RC":
                if self.metric_value == "X" or self.metric_value == "not_defined" or self.metric_value == "not defined":
                    self.report_confidence_value = Metrics.remediation_level.not_defined
                elif self.metric_value == "C" or self.metric_value == "confirmed":
                    self.report_confidence_value = Metrics.report_confidence.confirmed
                elif self.metric_value == "R" or self.metric_value == "reasonable":
                    self.report_confidence_value = Metrics.report_confidence.reasonable
                elif self.metric_value == "U" or self.metric_value == "unknown":
                    self.report_confidence_value = Metrics.report_confidence.unknown

        return (self.attack_vector_value, self.attack_complexity_value, self.user_interaction_value,
                self.privileges_required_value, self.confidentiality_value, self.integrity_value,
                self.availability_value, self.exploit_code_maturity_value, self.remediation_level_value,
                self.report_confidence_value, self.scope_value)

    def cvss_base_score(self):
        """ call the CVSS v3 Base (in order exploitability then impact then base).
        :return: the CVSS v3 Base score value
        """
        self.get_vectors()
        self.exploitability_sub_score_value = exploitability_sub_score(self.attack_vector_value,
                                                                       self.attack_complexity_value,
                                                                       self.privileges_required_value,
                                                                       self.user_interaction_value)

        self.impact_sub_score_value = impact_sub_score(self.availability_value, self.confidentiality_value,
                                                       self.integrity_value)

        self.cvss_base_score_value = cvss_base_formula(self.impact_sub_score_value, self.scope_value,
                                                       self.exploitability_sub_score_value)
        return self.cvss_base_score_value

    def cvss_temporal_score(self):
        """ call the CVSS v3 Temporal formula. The CVSS base score is required but already calculated.
        :return: the CVSS v3 Temporal score value
        """
        self.cvss_temporal_score_value = cvss_temporal_formula(self.cvss_base_score_value,
                                                               self.exploit_code_maturity_value,
                                                               self.remediation_level_value,
                                                               self.report_confidence_value)
        return self.cvss_temporal_score_value

    # def cvss_environmental_score(self):
    # To be enabled in version 0.2
    # Formula is already done and tested.
    #     return self.cvss_environmental_score_value
