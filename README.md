# server-ci-helper

This is just a demo tool. Not for production use!

Get last module scan results from Halo, exit code based on critical/non-critical issue count.

## Requirements

* Docker engine
* Halo read-only API keys
* A server label to search for, which exists within the scope of the API key.

## Usage

### Set the environment variables:

| Variable name       | Purpose                                                                    |
|---------------------|----------------------------------------------------------------------------|
| HALO_API_KEY        | Read-only API key for Halo                                                 |
| HALO_API_SECRET_KEY | Secret corresponding to `HALO_API_KEY`                                     |
| SERVER_LABEL        | This is the server label we search for.                                    |
| SCAN_MODULE         | Pick one: `sva` or `csm`.                                                  |
| MAX_CRITICAL        | More than this many critical findings will cause a non-zero exit code.     |
| MAX_NON_CRITICAL    | More than this many non-critical findings will cause a non-zero exit code. |


### Run the tool

docker run -t --rm \
    -e "HALO_API_KEY=${HALO_API_KEY}" \
    -e "HALO_API_SECRET_KEY=${HALO_API_SECRET_KEY}" \
    -e "SERVER_LABEL=${SERVER_LABEL}" \
    -e "SCAN_MODULE=${SCAN_MODULE}" \
    -e "MAX_CRITICAL=${MAX_CRITICAL}" \
    -e "MAX_NON_CRITICAL=${MAX_NON_CRITICAL}" \
    halotools/server-ci-helper:latest

### Interpreting the results

A human-readable report will be printed to stdout, and the exit code will be
non-zero if the thresholds are exceeded for critical or non-critical.
