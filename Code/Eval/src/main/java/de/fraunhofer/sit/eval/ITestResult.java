package de.fraunhofer.sit.eval;

import java.util.Map;

import de.fraunhofer.sit.specifications.executionprofile.testsuite.Testsuite;

public interface ITestResult {
	boolean exploitDetected();

	boolean exploitExpected();

	Testsuite getTestSuite();

	String getKey();

	default String toStringInternal() {
		return "TestResult [testSuite=" + getTestSuite() + ", key=" + getKey() + ", exploitDetected="
				+ exploitDetected() + ", exploitExpected=" + exploitExpected() + "]";
	}
}
