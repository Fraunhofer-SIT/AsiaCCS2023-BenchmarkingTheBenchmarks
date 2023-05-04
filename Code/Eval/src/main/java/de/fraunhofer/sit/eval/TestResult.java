package de.fraunhofer.sit.eval;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import de.fraunhofer.sit.specifications.executionprofile.testsuite.Testsuite;
import de.fraunhofer.sit.specifications.testcases.TestCase;

/**
 * Groups test cases among different attack patterns
 */
public class TestResult implements ITestResult {
	private List<SingleTestResult> results = new ArrayList<>();
	private Testsuite testSuite;
	private Boolean exploitExpected;
	private boolean exploitDetected;
	private String key;
	private Map<String, Boolean> exploitDetectedForExecutionProfile = new HashMap<>();
	private TestCase testcase;
	private int failedCaseCount = 0;
	public void add(SingleTestResult r) {
		testSuite = checkDisagree(testSuite, r.getTestSuite());
		exploitExpected = checkDisagree(exploitExpected, r.exploitExpected());
		key = checkDisagree(key, r.getKey());
		testcase = r.getTestCaseInfo().testCase;
		exploitDetectedForExecutionProfile.merge(r.getExecutionProfile(), r.exploitDetected(), Boolean::logicalOr);
		if (r.exploitDetected())
			// one is enough
			exploitDetected = true;
		if (!r.getHasFoundResult())
			// at least one case failed
			failedCaseCount++;
		results.add(r);
	}

	private static <T> T checkDisagree(T old, T newV) {
		if (old == null)
			return newV;
		if (!old.equals(newV))
			throw new RuntimeException("Disagreement: " + old + " vs " + newV);
		return newV;
	}

	public Testsuite getTestSuite() {
		return testSuite;
	}

	@Override
	public boolean exploitDetected() {
		return exploitDetected;
	}

	@Override
	public boolean exploitExpected() {
		return exploitExpected;
	}

	@Override
	public String getKey() {
		return key;
	}

	@Override
	public String toString() {
		return "TestResult [testSuite=" + getTestSuite() + ", key=" + getKey() + ", exploitDetected="
				+ exploitDetectedForExecutionProfile.toString() + ", exploitExpected=" + exploitExpected() + "]";	}
	
	public boolean exploitDetectedOnAllExecutionProfiles() {
		// return true if exploit was detected on all execution profiles (servlet containers)
		return exploitDetectedForExecutionProfile.values().stream().allMatch((detected) -> detected); 
	}
	public TestCase getTestcase() {
		return testcase;
	}
	public Map<String, Boolean> getExploitDetectedForExecutionProfile() {
		return exploitDetectedForExecutionProfile;
	}

	public int getFailedCaseCount() {
		// TODO Auto-generated method stub
		return failedCaseCount;
	}
}
