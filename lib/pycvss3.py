#!/usr/bin/env python
# Copyright (C) 2015 ToolsWatch.org
# This file is part of vFeed Aggregated Vulnerability Database Community

from metrics import Metrics
from formulas import *


class CVSS3(object):
    def __init__(self, vector):
        self.vectors = vector.split('/')

        # case of temporal vector not set
        self.ecm_metric = "unset"
        self.rl_metric = "unset"
        self.rc_metric = "unset"

        # case of environmental metrics not set
        self.cr_metric = "unset"
        self.ir_metric = "unset"
        self.ar_metric = "unset"

        # case of modified base metrics not set
        self.mav_metric = "unset"
        self.mac_metric = "unset"
        self.mpr_metric = "unset"
        self.mui_metric = "unset"
        self.mc_metric = "unset"
        self.mi_metric = "unset"
        self.ma_metric = "unset"

    def get_vectors(self):
        """ Extract metrics from CVSS v3 vector format and set value of metrics to the appropriate value
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
                self.ecm_metric = "set"
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
            else:
                if self.ecm_metric != "set":
                    self.exploit_code_maturity_value = Metrics.exploit_code_maturity.not_defined

            if self.metric_vector == "RL":
                self.rl_metric = "set"
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
            else:
                if self.rl_metric != "set":
                    self.remediation_level_value = Metrics.remediation_level.not_defined

            if self.metric_vector == "RC":
                self.rc_metric = "set"
                if self.metric_value == "X" or self.metric_value == "not_defined" or self.metric_value == "not defined":
                    self.report_confidence_value = Metrics.remediation_level.not_defined
                elif self.metric_value == "C" or self.metric_value == "confirmed":
                    self.report_confidence_value = Metrics.report_confidence.confirmed
                elif self.metric_value == "R" or self.metric_value == "reasonable":
                    self.report_confidence_value = Metrics.report_confidence.reasonable
                elif self.metric_value == "U" or self.metric_value == "unknown":
                    self.report_confidence_value = Metrics.report_confidence.unknown
            else:
                if self.rc_metric != "set":
                    # Assigning the default value in case
                    self.report_confidence_value = Metrics.report_confidence.not_defined

            if self.metric_vector == "CR":
                self.cr_metric = "set"
                if self.metric_value == "X" or self.metric_value == "not_defined" or self.metric_value == "not defined":
                    self.confidentiality_requirement_value = Metrics.cia_requirement.not_defined
                elif self.metric_value == "H" or self.metric_value == "high":
                    self.confidentiality_requirement_value = Metrics.cia_requirement.high
                elif self.metric_value == "M" or self.metric_value == "medium":
                    self.confidentiality_requirement_value = Metrics.cia_requirement.medium
                elif self.metric_value == "L" or self.metric_value == "low":
                    self.confidentiality_requirement_value = Metrics.cia_requirement.low
            else:
                if self.cr_metric != "set":
                    self.confidentiality_requirement_value = Metrics.cia_requirement.not_defined
            if self.metric_vector == "IR":
                self.ir_metric = "set"
                if self.metric_value == "X" or self.metric_value == "not_defined" or self.metric_value == "not defined":
                    self.integrity_requirement_value = Metrics.cia_requirement.not_defined
                elif self.metric_value == "H" or self.metric_value == "high":
                    self.integrity_requirement_value = Metrics.cia_requirement.high
                elif self.metric_value == "M" or self.metric_value == "medium":
                    self.integrity_requirement_value = Metrics.cia_requirement.medium
                elif self.metric_value == "L" or self.metric_value == "low":
                    self.integrity_requirement_value = Metrics.cia_requirement.low
            else:
                if self.ir_metric != "set":
                    self.integrity_requirement_value = Metrics.cia_requirement.not_defined

            if self.metric_vector == "AR":
                self.ar_metric = "set"
                if self.metric_value == "X" or self.metric_value == "not_defined" or self.metric_value == "not defined":
                    self.availability_requirement_value = Metrics.cia_requirement.not_defined
                elif self.metric_value == "H" or self.metric_value == "high":
                    self.availability_requirement_value = Metrics.cia_requirement.high
                elif self.metric_value == "M" or self.metric_value == "medium":
                    self.availability_requirement_value = Metrics.cia_requirement.medium
                elif self.metric_value == "L" or self.metric_value == "low":
                    self.availability_requirement_value = Metrics.cia_requirement.low
            else:
                if self.ar_metric != "set":
                    self.availability_requirement_value = Metrics.cia_requirement.not_defined

            if self.metric_vector == "MAV":
                self.mav_metric = "set"
                if self.metric_value == "X" or self.metric_value == "not_defined" or self.metric_value == "not defined":
                    self.attack_vector_value_modified = Metrics.attack_vector.not_defined
                elif self.metric_value == "N" or self.metric_value == "network":
                    self.attack_vector_value_modified = Metrics.attack_vector.network
                elif self.metric_value == "A" or self.metric_value == "adjacent_network":
                    self.attack_vector_value_modified = Metrics.attack_vector.adjacent_network
                elif self.metric_value == "L" or self.metric_value == "local":
                    self.attack_vector_value_modified = Metrics.attack_vector.local
                elif self.metric_value == "P" or self.metric_value == "physical":
                    self.attack_vector_value_modified = Metrics.attack_vector.physical
            else:
                if self.mav_metric != "set":
                    self.attack_vector_value_modified = Metrics.attack_vector.not_defined

            if self.metric_vector == "MAC":
                self.mac_metric = "set"
                if self.metric_value == "X" or self.metric_value == "not_defined" or self.metric_value == "not defined":
                    self.attack_complexity_value_modified = Metrics.attack_complexity.not_defined
                elif self.metric_value == "L" or self.metric_value == "low":
                    self.attack_complexity_value_modified = Metrics.attack_complexity.low
                elif self.metric_value == "H" or self.metric_value == "high":
                    self.attack_complexity_value_modified = Metrics.attack_complexity.high
            else:
                if self.mac_metric != "set":
                    self.attack_complexity_value_modified = Metrics.attack_complexity.not_defined

            # Assigning the appropriate value to MPR depending on the Modified Scope. See the formula.
            if self.metric_vector == "MS":
                self.scope_value_modified = self.metric_value
                # getting the value of MPR vector from the original splitted vectors
                self.splitted_3 = self.vectors[16:17][0].split(':')
                self.metric_vector = self.splitted_3[0]
                self.metric_value = self.splitted_3[1]
                if self.scope_value_modified == "C" or self.scope_value_modified == "changed":
                    self.scope_value_modified = "changed"
                    if self.metric_vector == "MPR":
                        self.mpr_metric = "set"
                        if self.metric_value == "X" or self.metric_value == "not_defined" or self.metric_value == "not defined":
                            self.privileges_required_value_modified = Metrics.privileges_required_changed.not_defined
                        elif self.metric_value == "N" or self.metric_value == "none":
                            self.privileges_required_value_modified = Metrics.privileges_required_changed.none
                        elif self.metric_value == "L" or self.metric_value == "low":
                            self.privileges_required_value_modified = Metrics.privileges_required_changed.low
                        elif self.metric_value == "H" or self.metric_value == "high":
                            self.privileges_required_value_modified = Metrics.privileges_required_changed.high
                    else:
                        if self.mpr_metric != "set":
                            self.privileges_required_value_modified = Metrics.privileges_required_changed.not_defined
                else:
                    self.scope_value_modified = "unchanged"
                    if self.metric_value == "X" or self.metric_value == "not_defined" or self.metric_value == "not defined":
                        self.privileges_required_value_modified = Metrics.privileges_required.not_defined
                    elif self.metric_value == "N" or self.metric_value == "none":
                        self.privileges_required_value_modified = Metrics.privileges_required.none
                    elif self.metric_value == "L" or self.metric_value == "low":
                        self.privileges_required_value_modified = Metrics.privileges_required.low
                    elif self.metric_value == "H" or self.metric_value == "high":
                        self.privileges_required_value_modified = Metrics.privileges_required.high
                    else:
                        raise Exception, "(MPR) Modified Privileges Required metric is not correct"

            if self.metric_vector == "MUI":
                self.mui_metric = "set"
                if self.metric_value == "X" or self.metric_value == "not_defined" or self.metric_value == "not defined":
                    self.user_interaction_value_modified = Metrics.user_interaction.not_defined
                elif self.metric_value == "N" or self.metric_value == "none":
                    self.user_interaction_value_modified = Metrics.user_interaction.none
                elif self.metric_value == "R" or self.metric_value == "required":
                    self.user_interaction_value_modified = Metrics.user_interaction.required
            else:
                if self.mui_metric != "set":
                    self.user_interaction_value_modified = Metrics.user_interaction.not_defined

            if self.metric_vector == "MC":
                self.mc_metric = "set"
                if self.metric_value == "X" or self.metric_value == "not_defined" or self.metric_value == "not defined":
                    self.confidentiality_value_modified = Metrics.cia_impact.not_defined
                elif self.metric_value == "L" or self.metric_value == "low":
                    self.confidentiality_value_modified = Metrics.cia_impact.low
                elif self.metric_value == "H" or self.metric_value == "high":
                    self.confidentiality_value_modified = Metrics.cia_impact.high
                elif self.metric_value == "N" or self.metric_value == "none":
                    self.confidentiality_value_modified = Metrics.cia_impact.none
            else:
                if self.mc_metric != "set":
                    self.confidentiality_value_modified = Metrics.cia_impact.not_defined

            if self.metric_vector == "MI":
                self.mi_metric = "set"
                if self.metric_value == "X" or self.metric_value == "not_defined" or self.metric_value == "not defined":
                    self.integrity_value_modified = Metrics.attack_vector.not_defined
                elif self.metric_value == "L" or self.metric_value == "low":
                    self.integrity_value_modified = Metrics.cia_impact.low
                elif self.metric_value == "H" or self.metric_value == "high":
                    self.integrity_value_modified = Metrics.cia_impact.high
                elif self.metric_value == "N" or self.metric_value == "none":
                    self.integrity_value_modified = Metrics.cia_impact.none
            else:
                if self.mi_metric != "set":
                    self.integrity_value_modified = Metrics.cia_impact.not_defined

            if self.metric_vector == "MA":
                self.ma_metric = "set"
                if self.metric_value == "X" or self.metric_value == "not_defined" or self.metric_value == "not defined":
                    self.availability_value_modified = Metrics.cia_impact.not_defined
                elif self.metric_value == "L" or self.metric_value == "low":
                    self.availability_value_modified = Metrics.cia_impact.low
                elif self.metric_value == "H" or self.metric_value == "high":
                    self.availability_value_modified = Metrics.cia_impact.high
                elif self.metric_value == "N" or self.metric_value == "none":
                    self.availability_value_modified = Metrics.cia_impact.none
            else:
                if self.ma_metric != "set":
                    self.availability_value_modified = Metrics.cia_impact.not_defined

        return

    def cvss_base_score(self):
        """ call the CVSS v3 Base (in order exploitability then impact then base).
        :return: the CVSS v3 Base score value with its risk level
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

        self.cvss_base_risk_level = self.risk_score(self.cvss_base_score_value)

        return (self.cvss_base_score_value, self.cvss_base_risk_level)

    def cvss_temporal_score(self):
        """ call the CVSS v3 Temporal formula. The CVSS base score is required but already calculated.
        :return: the CVSS v3 Temporal score value with its risk level
        """

        self.cvss_temporal_score_value = cvss_temporal_formula(self.cvss_base_score_value,
                                                               self.exploit_code_maturity_value,
                                                               self.remediation_level_value,
                                                               self.report_confidence_value)

        self.cvss_temporal_risk_level = self.risk_score(self.cvss_temporal_score_value)

        return (self.cvss_temporal_score_value, self.cvss_temporal_risk_level)

    def cvss_environmental_score(self):
        """ call the CVSS v3 Environmental formula (in order exp. sub score, impact sub score)
        :return: the CVSS v3 Environmental score value with its risk level
        """
        self.exploitability_sub_score_value_modified = exploitability_sub_score_modified(
            self.attack_vector_value_modified,
            self.attack_complexity_value_modified,
            self.privileges_required_value_modified,
            self.user_interaction_value_modified)

        self.impact_sub_score_value_modified = impact_sub_score_modified(self.availability_value_modified,
                                                                         self.confidentiality_value_modified,
                                                                         self.integrity_value_modified,
                                                                         self.confidentiality_requirement_value,
                                                                         self.integrity_requirement_value,
                                                                         self.availability_requirement_value)

        self.cvss_environmental_value = cvss_environmental_formula(self.impact_sub_score_value_modified,
                                                                   self.exploitability_sub_score_value_modified,
                                                                   self.exploit_code_maturity_value,
                                                                   self.remediation_level_value,
                                                                   self.report_confidence_value,
                                                                   self.scope_value_modified)

        self.cvss_environmental_risk_level = self.risk_score(self.cvss_environmental_value)

        return (self.cvss_environmental_value, self.cvss_environmental_risk_level)

    def risk_score(self, score):
        """
        :param score: risk values
        :return:  the qualitative risk rating values from none to critical
        """
        if score == float(0):
            self.risk_level = "None"
        elif score >= float(0.1) and score <= float(3.9):
            self.risk_level = "Low"
        elif score >= float(4.0) and score <= float(6.9):
            self.risk_level = "Medium"
        elif score >= float(7.0) and score <= float(8.9):
            self.risk_level = "High"
        elif score >= float(9.0) and score <= float(10.0):
            self.risk_level = "Critical"
        return self.risk_level
