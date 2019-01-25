import os
import pprint
import sys
import time

import cloudpassage


def main():
    key = os.getenv("HALO_API_KEY")
    secret = os.getenv("HALO_API_SECRET_KEY")
    module = os.getenv("SCAN_MODULE")
    server_label = os.getenv("SERVER_LABEL")

    if None in [key, secret]:
        print("Missing Halo auth information!")
        sys.exit(2)

    if module not in ["csm", "svm"]:
        print("{} is not a valid module!".format(module))
        sys.exit(2)

    if server_label is None:
        print("Need a server label!")
        sys.exit(2)

    # Set up CloudPassage API abstractions
    session = cloudpassage.HaloSession(key, secret)
    server = cloudpassage.Server(session)
    scan = cloudpassage.Scan(session)

    results = None
    iterations = 0
    clean_enough = False

    while not results:
        iterations += 1
        print("Waiting for server {} to appear...".format(server_label))
        if iterations > 10:
            results = "Unable to get scan results! Exiting!"
            clean_enough = False
            break
        try:
            server_id = server.list_all(server_label=server_label)[0]["id"]
            print("Server ID: {}".format(server_id))
            scan_output = scan.last_scan_results(server_id, module)
            # pprint.pprint(scan_output)
            results, clean_enough = handle_results(scan_output)
        except IndexError:
            print("Waiting for server {} to appear...".format(server_label))
            time.sleep(30)
        except cloudpassage.CloudPassageResourceExistence:
            print("Waiting on {} scan to complete...".format(module))
            time.sleep(30)
    if not clean_enough:
        print(results)
        sys.exit(2)
    else:
        print(results)
    return


def handle_results(scan_output):
    results = ""
    clean_enough = True
    if "scan" not in scan_output:  # Scan is incomplete
        print("No findings in scan results, wait and retry...")
        time.sleep(30)
        return (results, clean_enough)
    critical_threshold = int(os.getenv("MAX_CRITICAL", 0))
    non_critical_threshold = int(os.getenv("MAX_NON_CRITICAL", 0))
    criticals = scan_output["scan"]["critical_findings_count"]
    non_criticals = scan_output["scan"]["non_critical_findings_count"]
    results += "Halo scan: https://portal.cloudpassage.com/snapshot/servers/{}/scans/{}\n".format(scan_output["scan"]["server_id"], scan_output["scan"]["id"])
    if criticals > critical_threshold:
        results += "Maximum number of critical findings exceeded: {} > {}\n".format(criticals, critical_threshold)
        clean_enough = False
    if non_criticals > non_critical_threshold:
        results += "Maximum number of non-critical findings exceeded: {} > {}\n".format(non_criticals, non_critical_threshold)
        clean_enough = False
    for finding in scan_output["scan"]["findings"]:
        if finding["status"] == "bad":
            if "rule_name" in finding:
                results += "Critical: {} Rule name: {}\n".format(finding["critical"], finding["rule_name"])  # NOQA
            elif "package_name" in finding:
                # pprint.pprint(finding)
                cves = ", ".join(x["cve_entry"]
                                 for x in finding["cve_entries"])
                results += "Critical: {} Package: {}  Version: {}  CVEs: {}\n".format(finding["critical"], finding["package_name"], finding["package_version"], cves)
    return (results, clean_enough)


if __name__ == "__main__":
    main()
