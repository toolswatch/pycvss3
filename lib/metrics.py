#!/usr/bin/env python
# Copyright (C) 2015 ToolsWatch.org
# This file is part of vFeed Aggregated Vulnerability Database Community


class Value:
    def __init__(self, **entries):
        self.__dict__.update(entries)


class Metrics:
    """
    This class returns the metric values as defined by the CVSS v3 specification doc. https://www.first.org/cvss/specification-document
    I added not_defined key to base metrics to deal with the Modified Base Metrics as they have the same values
    as the corresponding Base Metrics
    """

    # Base Metrics
    attack_vector = Value(not_defined=float(0.85), network=float(0.85), adjacent_network=float(0.62), local=float(0.55),
                          physical=float(0.20))
    attack_complexity = Value(not_defined=float(0.77), low=float(0.77), high=float(0.44))
    privileges_required = Value(not_defined=float(0.85), none=float(0.85), low=float(0.62), high=float(0.27))
    privileges_required_changed = Value(not_defined=float(0.85), none=float(0.85), low=float(0.68), high=float(0.50))
    user_interaction = Value(not_defined=float(0.85), none=float(0.85), required=float(0.62))
    cia_impact = Value(not_defined=float(0.56), high=float(0.56), low=float(0.22), none=float(0))

    # Temporal Metrics
    exploit_code_maturity = Value(not_defined=float(1.0), high=float(1), functional=float(0.97),
                                  proof_of_concept=float(0.94), unproven=float(0.91))
    remediation_level = Value(not_defined=float(1.0), unavailable=float(1), workaround=float(0.97),
                              temporary_fix=float(0.96), official_fix=float(0.95))
    report_confidence = Value(not_defined=float(1.0), confirmed=float(1), reasonable=float(0.96), unknown=float(0.92))

    # Environmental Metrics
    cia_requirement = Value(not_defined=float(1.0), high=float(1.5), medium=float(1.0), low=float(0.50))
