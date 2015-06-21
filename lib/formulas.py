#!/usr/bin/env python
# Copyright (C) 2015 ToolsWatch.org
# This file is part of vFeed Aggregated Vulnerability Database Community

import math


def exploitability_sub_score(attack_vector_value, attack_complexity_value, privileges_required_value,
                             user_interaction_value):
    """
    :param attack_vector_value:
    :param attack_complexity_value:
    :param privileges_required_value:
    :param user_interaction_value:
    :return: the exploitability sub score required for the CVSS Base
    """
    exploitability_sub_score_value = 8.22 * attack_vector_value * attack_complexity_value * privileges_required_value * \
                                     user_interaction_value
    return exploitability_sub_score_value


def exploitability_sub_score_modified(attack_vector_value_modified, attack_complexity_value_modified,
                                      privileges_required_value_modified,
                                      user_interaction_value_modified):
    """
    :param attack_vector_value_modified:
    :param attack_complexity_value_modified:
    :param privileges_required_value_modified:
    :param user_interaction_value_modified:
    :return: The modified exploitability sub score as required by the Environmental score
    """
    exploitability_sub_score_value_modified = 8.22 * attack_vector_value_modified * attack_complexity_value_modified * privileges_required_value_modified * \
                                              user_interaction_value_modified
    return exploitability_sub_score_value_modified

def impact_sub_score(availability_value, confidentiality_value, integrity_value):
    """
    :param availability_value:
    :param confidentiality_value:
    :param integrity_value:
    :return: Impact sub score value as required by the Base score
    """
    impact_sub_score_value = 1 - ((1 - confidentiality_value) * (1 - integrity_value) * (1 - availability_value))
    return impact_sub_score_value


def impact_sub_score_modified(availability_value_modified, confidentiality_value_modified, integrity_value_modified,
                              confidentiality_requirement_value, integrity_requirement_value,
                              availability_requirement_value):
    """
    :param availability_value_modified:
    :param confidentiality_value_modified:
    :param integrity_value_modified:
    :param confidentiality_requirement_value:
    :param integrity_requirement_value:
    :param availability_requirement_value:
    :return: the modified Impact sub score as required by the Environmental score
    """
    impact_sub_score_value_modified = min(0.915, 1 - (
        1 - confidentiality_value_modified * confidentiality_requirement_value) * (
                                              1 - integrity_value_modified * integrity_requirement_value) * (
                                              1 - availability_value_modified * availability_requirement_value))
    return impact_sub_score_value_modified


def cvss_base_formula(impact_sub_score_value, scope_value, exploitability_sub_score_value):
    """
    :param impact_sub_score_value:
    :param scope_value:
    :param exploitability_sub_score_value:
    :return: the cvss base value
    """
    if scope_value == "unchanged":
        impact_value = 6.42 * impact_sub_score_value
        cvss_base_value = min(10, impact_value + exploitability_sub_score_value)

    elif scope_value == "changed":
        impact_value = 7.52 * (impact_sub_score_value - 0.029) - 3.25 * math.pow(
            impact_sub_score_value - 0.02, 15)
        cvss_base_value = min(10, 1.08 * (impact_value + exploitability_sub_score_value))

    if impact_sub_score_value <= 0:
        cvss_base_value = float(0.0)
    else:
        cvss_base_value = math.ceil(cvss_base_value * 10) / 10
    return cvss_base_value


def cvss_temporal_formula(cvss_base_value, exploit_code_maturity_value, remediation_level_value,
                          report_confidence_value):
    """
    :param cvss_base_value:
    :param exploit_code_maturity_value:
    :param remediation_level_value:
    :param report_confidence_value:
    :return: the temporal score value
    """
    cvss_temporal_value = cvss_base_value * exploit_code_maturity_value * remediation_level_value * \
                          report_confidence_value
    cvss_temporal_value = math.ceil(cvss_temporal_value * 10) / 10
    return cvss_temporal_value


def cvss_environmental_formula(impact_sub_score_value_modified, exploitability_sub_score_value_modified,
                             exploit_code_maturity_value, remediation_level_value, report_confidence_value,
                             scope_value_modified):
    """
    :param impact_sub_score_value_modified:
    :param exploitability_sub_score_value_modified:
    :param exploit_code_maturity_value:
    :param remediation_level_value:
    :param report_confidence_value:
    :param scope_value_modified:
    :return: the environmental score value
    """
    if scope_value_modified == "unchanged":
        impact_value_modified = 6.42 * impact_sub_score_value_modified
        temp_score = min(10, impact_value_modified + exploitability_sub_score_value_modified)
        temp_score2 = math.ceil(temp_score * 10) / 10
        temp_score3 = temp_score2 * exploit_code_maturity_value * remediation_level_value * report_confidence_value

    else:
        scope_value_modified == "changed"
        impact_value_modified = 7.52 * (impact_sub_score_value_modified - 0.029) - 3.25 * math.pow(
            impact_sub_score_value_modified - 0.02, 15)
        temp_score = min(10, 1.08 * (impact_value_modified + exploitability_sub_score_value_modified))
        temp_score2 = math.ceil(temp_score * 10) / 10
        temp_score3 = temp_score2 * exploit_code_maturity_value * remediation_level_value * report_confidence_value

    if impact_sub_score_value_modified <= 0:
        cvss_environmental_value = float(0.0)
        return cvss_environmental_value
    else:
        cvss_environmental_value = math.ceil(temp_score3 * 10) / 10
        return cvss_environmental_value
