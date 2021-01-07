# server-ci-helper

Get last module scan results from Halo and outputs report(s) in HTML format
Scan pass/fail criteria include maximum number of critical/non-critical issues
and maximum CVSS score.

## Requirements

* Docker engine
* Halo API key and secret (API key with auditor privileges recommended)
* A CSP instance ID as input, to get the scan results for the launched test instance

## Usage

### Set the environment variables:

| Variable name       | Purpose                                                                    |
|---------------------|----------------------------------------------------------------------------|
| HALO_API_KEY        | Read-only API key for Halo                                                 |
| HALO_API_SECRET_KEY | Secret corresponding to `HALO_API_KEY`                                     |
| INSTANCE_ID         | Unique identifier to search for test instance and get scan results         |
| SERVER_LABEL        | Optional - If instance is not found with INSTANCE_ID, then this fallback identifier will be used. Specify the server label when installing the Halo agent using the "--server-label=yourLabel" flag|
| SCAN_MODULE         | Pick one or both: `sva` or `csm` or `sva,csm`                              |
| MAX_CRITICAL        | More than this number of critical findings will cause a test failure            |
| MAX_NON_CRITICAL    | More than this number non-critical findings will cause a test failure        |
| MAX_CVSS            | A maximum CVSS score among all CVEs greater than this will fail the test   |
| FAIL_EXIT_CODE      | Optional - Exit code that script returns when at least one test fails. Default is set to 2. You can use this option to set a custom exit code to mark the build unstable.|


### Run the tool

```buildoutcfg
docker run -t --rm \
    -v /host/directory/to/save/html/reports:/app/reports/html \
    -e "HALO_API_KEY=${HALO_CI_API_CREDS_USR}" \
    -e "HALO_API_SECRET_KEY=${HALO_CI_API_CREDS_PSW}" \
    -e "INSTANCE_ID=${INSTANCE_ID}" \
    -e "SCAN_MODULE=${SCAN_MODULE}" \
    -e "MAX_CRITICAL=${MAX_CRITICAL}" \
    -e "MAX_NON_CRITICAL=${MAX_NON_CRITICAL}" \
    -e "MAX_CVSS=${MAX_CVSS}" \
    halotools/server-ci-helper:latest
```


### Interpreting the results

An HTML report will be saved to "/app/reports/html" when run inside a container,
or "reports/html" if run as stand-alone. To be able to access the HTML reports
outside of the container, you must mount a host directory to "/app/reports/html"
as shown in the above example. Test results based on above criteria
will be displayed at the top. Vulnerabilities found are displayed with 
detail CVE information. Similarly, configuration findings are displayed with the
detailed check results and remediation information if available.

<!---
#CPTAGS:community-supported integration deployment
#TBICON:images/python_icon.png
-->
