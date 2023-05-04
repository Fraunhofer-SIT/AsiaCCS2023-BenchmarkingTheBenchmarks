package de.fraunhofer.sit.eval;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class EvalTableEntry implements Comparable<EvalTableEntry> {
	String testsuite;
	int cwe;
	boolean exploitExpected;
	boolean exploitDetected;
	Map<String, Boolean> exploitDetectedForExecutionProfile;
	String noExploitExpectedReason;
	String executionProfileResults;
	int attackPatternCount;
	int failedCaseCount;
	public EvalTableEntry(String testsuite, int cwe, int attackPatternCount, boolean exploitExpected, boolean resultDetected, int failedCaseCount,
			Map<String, Boolean> exploitDetectedForExecutionProfile, String noExploitExpectedReason) {
		super();
		this.testsuite = testsuite;
		this.failedCaseCount = failedCaseCount;
		this.cwe = cwe;
		this.attackPatternCount = attackPatternCount;
		this.exploitExpected = exploitExpected;
		this.exploitDetected = resultDetected;
		this.exploitDetectedForExecutionProfile = exploitDetectedForExecutionProfile;
		this.noExploitExpectedReason = noExploitExpectedReason;
		if (!exploitDetected && noExploitExpectedReason == null) {
			noExploitExpectedReason = "null";
		}
		executionProfileResults = "";
		if (exploitExpected) {
			ArrayList<String> executionProfiles = new ArrayList();
			executionProfiles.addAll(exploitDetectedForExecutionProfile.keySet());
			Collections.sort(executionProfiles);
			
			for (String s : executionProfiles) {
				executionProfileResults += s + "=" + exploitDetectedForExecutionProfile.get(s) + " "; 
			}
		}
		
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(cwe, exploitDetected, executionProfileResults, exploitExpected,
				noExploitExpectedReason, testsuite);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		EvalTableEntry other = (EvalTableEntry) obj;
		return cwe == other.cwe && exploitDetected == other.exploitDetected
				&& Objects.equals(executionProfileResults, other.executionProfileResults)
				&& exploitExpected == other.exploitExpected
				&& Objects.equals(noExploitExpectedReason, other.noExploitExpectedReason)
				&& Objects.equals(testsuite, other.testsuite);
	}
	@Override
	public int compareTo(EvalTableEntry o) {
		int r = testsuite.compareTo(o.testsuite);
		if (r != 0)
			return r;
		r = Integer.compare(cwe, o.cwe);
		if (r != 0)
			return r;
		r = Boolean.compare(exploitExpected, o.exploitExpected);
		if (r != 0) 
			return r;
		if (exploitExpected ) {
			// both expect an exploit
			return executionProfileResults.compareTo(o.executionProfileResults);
		} else {
			// both expect no exploit
			return noExploitExpectedReason.compareTo(o.noExploitExpectedReason);
		}
	}
	@Override
	public String toString() {
		
		return String.format("%s;%d;%d;%b;%b;%d;%s;%s", testsuite, cwe, attackPatternCount, exploitExpected, exploitDetected,failedCaseCount, executionProfileResults, noExploitExpectedReason  );
	}
}