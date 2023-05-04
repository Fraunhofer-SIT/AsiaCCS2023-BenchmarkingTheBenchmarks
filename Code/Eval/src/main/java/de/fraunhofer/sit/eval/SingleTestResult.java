package de.fraunhofer.sit.eval;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Properties;

import org.apache.commons.io.IOUtils;

import de.fraunhofer.sit.specifications.executionprofile.testsuite.Testsuite;

public class SingleTestResult implements ITestResult {

	private String attackPreset;
	private Testsuite testSuite;
	private String key;
	private String dateCreated;
	private boolean exploitDetected;
	private boolean exploitExpected;
	private TestCaseInfo testcaseinfo;
	private String testSuiteString;
	private String executionProfile;
	private boolean hasFoundResult;

	public SingleTestResult(Properties info, File log) throws IOException {
		testSuiteString= info.get("TestSuite").toString();
		if (testSuiteString.contains("@")) {
			// parse eval run with bad info file
			if (testSuiteString.contains("Juliet")) {
				testSuiteString = "juliet";
			} else if (testSuiteString.contains("OWASP")) {
				testSuiteString = "OWASP";
			} else {
				throw new RuntimeException("can't parse test suite");
			}
		}
		attackPreset = info.get("AttackPreset").toString();
		key = info.get("Key").toString();
		dateCreated = info.get("DateCreated").toString();
		executionProfile = info.getProperty("ExecutionProfile");
		if (executionProfile == null) {
			// backwards-compatability for last test run
			String containerDirName = log.getName();
			executionProfile = containerDirName.substring(containerDirName.lastIndexOf("_")+1);
		}
		List<String> logContent = null;
		try (FileInputStream fis = new FileInputStream(log)) {
			logContent = IOUtils.readLines(fis, "UTF-8");
		}
		hasFoundResult = false;
		for (String s : logContent) {
			if (s.contains("[EXPLOIT] result:")) {
				if (s.contains("Exploit detected"))
					exploitDetected = true;
				else if (s.contains("Exploit not detected"))
					exploitDetected = false;
				else
					throw new RuntimeException("Unknown state: " + s);
				hasFoundResult = true;
				break;
			}

		}
		
	}

	@Override
	public String toString() {
		return "TestResult [attackPreset=" + attackPreset + ", testSuite=" + testSuite + ", key=" + key
				+ ", dateCreated=" + dateCreated + ", exploitDetected=" + exploitDetected + ", exploitExpected="
				+ exploitExpected + ", hasFoundResult=" + hasFoundResult + "]";
	}

	public void setTestCase(TestCaseInfo t) {
		checkEquals(t.testCase.key, key);
		testSuite = t.testCase.testsuite;
		exploitExpected = t.testCase.exploitable;
		this.testcaseinfo = t;
	}

	private void checkEquals(Object a1, Object a2) {
		if (!a1.equals(a2))
			throw new RuntimeException("Mismatch: " + a1 + " vs " + a2);
	}

	@Override
	public boolean exploitDetected() {
		return exploitDetected;
	}

	@Override
	public boolean exploitExpected() {
		return exploitExpected;
	}

	public String getAttackPreset() {
		return attackPreset;
	}

	public String getKey() {
		return key;
	}

	public Testsuite getTestSuite() {
		return testSuite;
	}

	public TestCaseInfo getTestCaseInfo() {
		return testcaseinfo;
	}
	
	public String getExecutionProfile() {
		return executionProfile;
	}
	
	public String getTestSuiteString() {
		return testSuiteString;
	}
	public boolean getHasFoundResult() {
		return hasFoundResult;
	}
	
}
