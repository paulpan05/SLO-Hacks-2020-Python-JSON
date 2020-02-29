import requests
import json
import re

rCVEjson = requests.get('https://access.redhat.com/hydra/rest/securitydata/cve.json?package=nginx').json()
p = re.compile('[0-9]*\.[0-9]*')

result = dict()

for cve in rCVEjson:
    if cve["severity"] != "low":
        rCVE = requests.get(f'https://access.redhat.com/hydra/rest/securitydata/cve/{cve["CVE"]}').json()
        if "affected_release" in rCVE:
            for release in rCVE["affected_release"]:
                if "package" in release:
                    if "nginx" not in result:
                        result["nginx"] = dict()
                    nginxDict = result["nginx"]
                    if release["package"] not in nginxDict:
                        nginxDict[release["package"]] = dict()
                    nginxRelease = nginxDict[release["package"]]
                    if cve["CVE"] not in nginxRelease:
                        nginxRelease[cve["CVE"]] = dict()
                    nginxRelease[cve["CVE"]] = {"threat_severity": rCVE["threat_severity"]}

print(json.dumps(result, indent=2))
