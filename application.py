import os
import sys
import time
import datetime
import jinja2
from distutils.dir_util import copy_tree
from collections import defaultdict
import copy
import re
from pathlib import Path

import cloudpassage


def main():
    global FAIL_EXIT_CODE
    FAIL_EXIT_CODE = int(os.getenv("FAIL_EXIT_CODE", 2))
    start_time = datetime.datetime.now()
    copy_tree("static", "reports/html/static")
    Path("reports/html/cve").mkdir(parents=True, exist_ok=True)

    key = os.getenv("HALO_API_KEY")
    secret = os.getenv("HALO_API_SECRET_KEY")
    module_str = os.getenv("SCAN_MODULE")
    modules = module_str.split(",")
    instance_id = os.getenv("INSTANCE_ID")
    timeout = os.getenv("TIMEOUT")
    max_cvss_threshold = float(os.getenv("MAX_CVSS", 7))

    modules = [module.lower() for module in modules]
    modules = list(set(modules))

    session = cloudpassage.HaloSession(key, secret)
    validate_input(session, modules, instance_id, max_cvss_threshold)

    server = cloudpassage.Server(session)
    scan = cloudpassage.Scan(session)
    group = cloudpassage.ServerGroup(session)

    scanned_server = get_server(server, instance_id, start_time, timeout)

    server_id = scanned_server["id"]
    print(f"Server ID: {server_id}")

    modules = validate_csm(modules, scanned_server, group)

    scans = {}
    for module in modules:
        while True:
            try:
                scan_output = scan.last_scan_results(server_id, module)
            except cloudpassage.CloudPassageResourceExistence:
                check_timeout(start_time, timeout)
                print("Waiting on {} scan to complete...".format(module))
                time.sleep(30)
            if scan_output and "scan" in scan_output:
                scans[module] = scan_output["scan"]
                break
            check_timeout(start_time, timeout)
            print("Waiting on {} scan to complete...".format(module))
            time.sleep(30)

    build_success = process_scan(scans, scanned_server, session)

    if not build_success:
        print("Security scan results did not meet pass criteria")
        sys.exit(FAIL_EXIT_CODE)


def get_server(server, instance_id, start_time, timeout):
    while True:
        scanned_server = server.list_all(csp_instance_id=instance_id)
        if scanned_server:
            return scanned_server[0]
        check_timeout(start_time, timeout)
        print(f"Waiting for server {instance_id} to appear...")
        time.sleep(15)


def check_timeout(start_time, timeout):
    time_now = datetime.datetime.now()
    if timeout and time_now - start_time > datetime.timedelta(minutes=int(timeout)):
        print("Timeout exceeded: Exiting program")
        sys.exit(FAIL_EXIT_CODE)


def validate_csm(modules, scanned_server, group):
    if "csm" in modules:
        if not check_csm_exists(scanned_server, group):
            print("Configuration policy doesn't exist for test server. Please set policy for server group in Halo")
            modules.remove("csm")
            if not modules:
                sys.exit(FAIL_EXIT_CODE)
    return modules


def check_csm_exists(scanned_server, group):
    group_id = scanned_server["group_id"]
    group_obj = group.describe(group_id)
    if scanned_server.get("platform") == "windows":
        return group_obj.get("windows_policy_ids")
    else:
        return group_obj.get("policy_ids")


def validate_input(session, modules, instance_id, max_cvss):
    if not session.authenticate_client():
        print("Failed to authenticate client: Please check Halo credentials")
        sys.exit(FAIL_EXIT_CODE)

    invalids = []
    for mod in modules:
        if mod not in ["csm", "sva"]:
            invalids.append(mod)
    if invalids:
        print("{} are invalid modules".format(', '.join(invalid for invalid in invalids)))
        print("Supported modules are: 'sva, csm'")
        sys.exit(FAIL_EXIT_CODE)

    if not 0.0 <= max_cvss <= 10.0:
        print("Max_cvss value must be number between 0.0 and 10.0")
        sys.exit(FAIL_EXIT_CODE)

    if instance_id is None:
        print("Need an instance ID!")
        sys.exit(FAIL_EXIT_CODE)


def process_sva(sva_scan, server, session, tests):
    tests["max_criticals"]["actual"] = sva_scan["critical_findings_count"]
    tests["max_non_criticals"]["actual"] = sva_scan["non_critical_findings_count"]

    bad_findings = [finding for finding in sva_scan["findings"] if finding['status'] == 'bad']
    tests["max_cvss"]["actual"] = max(cve_entry["cvss_score"] for finding in bad_findings for cve_entry in finding["cve_entries"])

    if tests["max_criticals"]["actual"] > tests["max_criticals"]["threshold"]:
        tests["max_criticals"]["result"] = False
    if tests["max_non_criticals"]["actual"] > tests["max_non_criticals"]["threshold"]:
        tests["max_non_criticals"]["result"] = False
    if tests["max_cvss"]["actual"] > tests["max_cvss"]["threshold"]:
        tests["max_cvss"]["result"] = False

    cve_details = {}
    cve_detail = cloudpassage.CveDetails(session)

    for finding in bad_findings:
        finding["remote"] = "No"
        for cve_entry in finding["cve_entries"]:
            detail = cve_detail.describe(cve_entry["cve_entry"])
            cve_details[cve_entry["cve_entry"]] = detail
            if detail["CVSS Metrics"]["access_vector"] == "NETWORK":
                finding["remote"] = "Yes"

    scan_time = sva_scan["completed_at"]
    generate_sva_report(tests, bad_findings, server, cve_details, scan_time)

    return all(v["result"] for v in tests.values())


def process_csm(csm_scan, server, session, tests):
    scan = cloudpassage.Scan(session)
    policy = cloudpassage.ConfigurationPolicy(session)
    scan_details = scan.scan_details(csm_scan["id"])
    csm_policy_list = scan_details["policies"]
    csm_policies = [policy.describe(item["id"]) for item in csm_policy_list]
    rules_dict = {}
    for csm_policy in csm_policies:
        for rule in csm_policy["rules"]:
            rules_dict[rule["name"]] = rule

    tests["max_criticals"]["actual"] = csm_scan["critical_findings_count"]
    tests["max_non_criticals"]["actual"] = csm_scan["non_critical_findings_count"]

    if tests["max_criticals"]["actual"] > tests["max_criticals"]["threshold"]:
        tests["max_criticals"]["result"] = False
    if tests["max_non_criticals"]["actual"] > tests["max_non_criticals"]["threshold"]:
        tests["max_non_criticals"]["result"] = False

    bad_findings = [finding for finding in csm_scan["findings"] if finding['status'] == ('bad' or 'indeterminate')]
    scan_time = csm_scan["completed_at"]
    generate_csm_report(tests, bad_findings, server, scan_time, rules_dict, csm_policies)

    return all(v["result"] for v in tests.values())


def process_scan(scans, server, session):
    sva_passed = True
    csm_passed = True
    tests = defaultdict(dict)
    tests["max_cvss"]["threshold"] = float(os.getenv("MAX_CVSS", 7))
    tests["max_criticals"]["threshold"] = int(os.getenv("MAX_CRITICAL", 10))
    tests["max_non_criticals"]["threshold"] = int(os.getenv("MAX_NON_CRITICAL", 25))
    for v in tests.values():
        v["result"] = True

    if "sva" in scans:
        sva_passed = process_sva(scans["sva"], server, session, copy.deepcopy(tests))
    if "csm" in scans:
        csm_passed = process_csm(scans["csm"], server, session, copy.deepcopy(tests))

    return all([sva_passed, csm_passed])


def generate_csm_report(tests, bad_findings, server, scan_time, rules_dict, csm_policies):
    template_loader = jinja2.FileSystemLoader(searchpath="./templates")
    template_env = jinja2.Environment(loader=template_loader)
    template = template_env.get_template("csm_report.html")

    for finding in bad_findings:
        if finding["rule_remediation"]:
            tmp = re.sub(r'(```|#|/\b[A-Z][a-z]*(\s[A-Z][a-z]*)*\b(?=(?:[^```]*```[^```]*```)*[^```]*\Z)/)', r'\n\1', finding["rule_remediation"])
            formatted = re.sub(r'(```|/:(?=(?:[^```]*```[^```]*```)*[^```]*\Z)/)', r'\1\n', tmp)
            finding["rule_remediation"] = formatted.split('\n')

    rendered = template.render(tests=tests, findings=bad_findings, server=server, rules_dict=rules_dict,
                               scan_time=scan_time, csm_policies=csm_policies)

    with open(f"reports/html/halo_csm_results.html", "w") as file:
        file.write(rendered)


def generate_sva_report(tests, bad_findings, server, cve_details, scan_time):
    template_loader = jinja2.FileSystemLoader(searchpath="./templates")
    template_env = jinja2.Environment(loader=template_loader)
    sva_template = template_env.get_template("sva_report.html")
    sva_rendered = sva_template.render(tests=tests, findings=bad_findings, server=server, cve_details=cve_details,
                               scan_time=scan_time)

    with open(f"reports/html/halo_sva_results.html", "w") as file:
        file.write(sva_rendered)

    cve_template = template_env.get_template("cve_detail.html")
    for cve, detail in cve_details.items():
        cve_rendered = cve_template.render(cve=cve, cve_detail=detail)
        with open(f"reports/html/cve/{cve}.html", "w") as file:
            file.write(cve_rendered)


if __name__ == "__main__":
    main()
