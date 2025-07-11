#!/usr/bin/env python3

"""checkmk plugin for GENUA-EXTEND-MIB"""

from cmk.agent_based.v2 import (
    SimpleSNMPSection,
    SNMPTree,
    StringTable,
    State,
    CheckPlugin,
    DiscoveryResult,
    CheckResult,
    Service,
    Result,
    check_levels,
    all_of,
    exists,
)

from cmk.plugins.lib.genua import DETECT_GENUA

import re

Section = dict[str, dict[str, str]]


def parse_genua_extend(string_table: StringTable) -> Section:
    parsed = {}
    for line in string_table:
        extendName, extendDescription, extendStatus, extendPerformancedata = line
        extendPerformancedata = {
            name: val
            for name, val in [
                a.split("=") for a in extendPerformancedata.split(" ") if "=" in a
            ]
        }
        sub_parsed = {
            "extendName": extendName,
            "extendDescription": extendDescription,
            "extendStatus": int(extendStatus),
            "extendPerformancedata": extendPerformancedata,
        }
        parsed[extendName] = sub_parsed
    return parsed


snmp_section_genua_extend = SimpleSNMPSection(
    name="genua_extend",
    detect=all_of(
        DETECT_GENUA,
        exists(".1.3.6.1.4.1.3717.66.1.1.*"),  # genuaExtend
    ),
    fetch=SNMPTree(
        base=".1.3.6.1.4.1.3717.66.1.1",  # GENUA-EXTEND-MIB::extendTable
        oids=[
            "1",  # extendName
            "2",  # extendDescription
            "3",  # extendStatus
            "4",  # extendPerformancedata
        ],
    ),
    parse_function=parse_genua_extend,
)


def discover_genua_extend(section: Section) -> DiscoveryResult:
    for check in section.keys():
        yield Service(
            item=check,
        )


# Helpers


def float_ignore_uom(value: str) -> float:
    """16MB -> 16.0"""
    while value:
        try:
            return float(value)
        except ValueError:
            value = value[:-1]
    return 0.0


def uom_from_value(value: str) -> str:
    """16.2MB -> MB"""
    m = re.match(r"[0-9.]* ?(.*)", value)
    return m.group(1) if m else None


def render_value_func(uom):
    """Render function with supplied UOM"""

    def render_value(value):
        int_value = int(value)
        if value == int_value:
            value = int_value
        return f"{value} {uom}"

    return render_value


def parse_thresholds(t):
    """Parse simple Nagios-style thresholds
    '10', '10:' or '10:20' are supported, but not @, ~"""
    if ":" in t:
        upper, _, lower = t.partition(":")
        upper = float_or_none(upper)
        lower = float_or_none(lower)
        return lower, upper
    return float_or_none(t), None


def float_or_none(string):
    try:
        f = float(string)
        return f
    except ValueError:
        return None


def check_genua_extend(item: str, params: dict, section: Section) -> CheckResult:
    pe = section.get(item, {})
    statuscode = pe.get("extendStatus", 99)
    code2state = {0: State.OK, 1: State.WARN, 2: State.CRIT, 3: State.UNKNOWN}

    if statuscode in range(0, 4):
        yield Result(
            state=code2state[statuscode],
            summary=pe.get("extendDescription", "No Description"),
        )
    else:
        desc = pe.get("extendDescription", "No SNMP data")
        yield Result(state=State.UNKNOWN, summary=desc)
    extendPerformancedata = pe.get("extendPerformancedata", {})
    for name, value in extendPerformancedata.items():
        split_v = value.split(";")
        while len(split_v) <= 5:
            split_v.append("")
        value, warn, crit, min_bound, max_bound = split_v[0:5]
        check_params = {}

        min_bound = float_or_none(min_bound)
        max_bound = float_or_none(max_bound)
        crit_upper, crit_lower = parse_thresholds(crit)
        warn_upper, warn_lower = parse_thresholds(warn)

        if min_bound or max_bound:
            check_params["boundaries"] = (min_bound, max_bound)
        if warn_upper and crit_upper:
            check_params["levels_upper"] = ("fixed", (crit_upper, warn_upper))
        if warn_lower and crit_lower:
            check_params["levels_lower"] = ("fixed", (crit_lower, warn_lower))
        uom = uom_from_value(value)
        value = float_ignore_uom(value)
        if uom:
            check_params["render_func"] = render_value_func(uom)

        yield from check_levels(
            value, metric_name=name, label=name, notice_only=True, **check_params
        )


check_plugin_genua_extend = CheckPlugin(
    name="genua_extend",
    service_name="Extend %s",
    sections=["genua_extend"],
    discovery_function=discover_genua_extend,
    check_function=check_genua_extend,
    check_ruleset_name="genua_extend",
)
