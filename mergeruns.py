from sys import argv
import csv
from functools import cmp_to_key
files = argv[1:]
def parseRow(row):
    #print(row)
    testsuite,cwe,presetCount,exploitExpected,exploitDetected,failedRuns,executionProfileResults, noExploitExpectedReason,key = row
    rowstr = ";".join(row)
    return {
        "testsuite": testsuite,
        "cwe": int(cwe),
        "presetCount": int(presetCount),
        "exploitExpected": exploitExpected == "true",
        "exploitDetected": exploitDetected == "true",
        "failedRuns": int(failedRuns),
        "executionProfileResults": executionProfileResults,
        "noExploitExpectedReason": noExploitExpectedReason,
        "key": key,
        "rowstr":rowstr,
        "summarytablerow": "{};{};{};{};{};{}".format(testsuite, cwe, exploitExpected, exploitDetected, executionProfileResults, noExploitExpectedReason)
        }

def compareString(s1, s2):
    if (s1 == s2):
        return 0
    if s1 < s2:
        return -1
    return 1

def compareNumbers(s1, s2):
    if (s1 == s2):
        return 0
    if s1 < s2:
        return -1
    return 1

def compareRows(row1, row2):
    r = compareString(row1["testsuite"], row2["testsuite"])
    if (r != 0):
        return r
    r = compareNumbers(row1["cwe"], row2["cwe"])
    if r != 0:
        return r
    if row1["exploitExpected"] != row2["exploitExpected"]:
        if row1["exploitExpected"]:
            return 1
        else:
            return -1
    if row1["exploitExpected"]:
        return compareString(row1["executionProfileResults"], row2["executionProfileResults"])
    else:
        return compareString(row1["noExploitExpectedReason"], row2["noExploitExpectedReason"])

key_to_row = {}
for basefile in files:
    with open(basefile) as csvfile:
        reader = csv.reader(csvfile, delimiter=';', quotechar='"')
        for row in reader:
            r = parseRow(row)
            key_to_row[r["key"]] = r


vals = []
for v in key_to_row.values():
    vals.append(v)
sorted(vals,key=cmp_to_key(compareRows))
fulltable = open("fulltable.csv","w")
servlet_container_different_results = open("servlet_container_different_results.csv","w")
for r in vals:
    fulltable.write(r["rowstr"] + "\n")
    if ("true" in r["executionProfileResults"] and "false" in r["executionProfileResults"]):
        servlet_container_different_results.write(r["rowstr"] + "\n")
fulltable.close()
servlet_container_different_results.close()


summaryRows = []
rowToSummary = {}
for r in vals:
    if r["summarytablerow"] in rowToSummary:
        rowToSummary[r["summarytablerow"]]["count"] += 1
    else:
        rowToSummary[r["summarytablerow"]] = r
        r["count"] = 1
        summaryRows += [r]

summarytable = open("summary.csv", "w")
for r in summaryRows:
    if (r["testsuite"] == "juliet" and r["noExploitExpectedReason"] == "Not exploitable by design (OWASP)"):
        continue
    summarytable.write("{};{}\n".format(r["summarytablerow"], r["count"]))
summarytable.close()