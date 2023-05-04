package de.fraunhofer.sit.eval;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

public class Aggregation {

	List<TestResult> allResults = new ArrayList<>();
	public int expectedExploitable = 0, expectedNotExploitable = 0;
	public Rate<TestResult> tr;
	public Rate<TestResult> tpr, tnr, fpr, fnr, differentResultByExecutionProfile;

	public void aggregate(TestResult testResult) {
		allResults.add(testResult);
	}

	@Override
	public String toString() {
		return toString(false);
	}

	public void eval() {

		tpr = new Rate<TestResult>(allResults.size());
		tnr = new Rate<TestResult>(allResults.size());
		fpr = new Rate<TestResult>(allResults.size());
		fnr = new Rate<TestResult>(allResults.size());
		differentResultByExecutionProfile = new Rate<TestResult>(allResults.size());
		tr = new Rate<TestResult>();
		for (TestResult i : allResults) {
			if (i.exploitExpected())
				expectedExploitable++;
			else
				expectedNotExploitable++;
			if (!i.exploitDetectedOnAllExecutionProfiles()) {
				differentResultByExecutionProfile.count(i);
			}
			if (i.exploitDetected() == i.exploitExpected()) {
				tr.count(i);
				if (i.exploitDetected())
					tpr.count(i);
				else
					tnr.count(i);
			} else {
				tr.notCount();
				if (!i.exploitDetected()) {
					// exploit not detected, but expected
					fnr.count(i);
				} else {
					// exploit detected, but not expected
					fpr.count(i);
				}
			}
		}
	}

	public String toString(boolean verbose) {

		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		pw.println("Number of test cases: " + allResults.size());
		pw.println("Number of test cases, which claim to be exploitable: " + expectedExploitable);
		pw.println("Number of test cases, which claim to be NOT exploitable: " + expectedNotExploitable);
		pw.println("True positives: Claims to be exploitable and is exploitable: " + tpr);
		pw.println("True negatives: Claims to be NOT exploitable and is NOT exploitable: " + tnr);
		pw.println("False positives: Claims to be NOT exploitable and is exploitable: " + fpr);
		if (verbose) {
			fpr.print(pw);
		}
		pw.println("False negatives: Claims to be exploitable and is NOT exploitable: " + fnr);
		if (verbose) {
			fnr.print(pw);
		}
		pw.println("Test cases with different results by execution profile: " + differentResultByExecutionProfile);
		if (verbose) {
			differentResultByExecutionProfile.print(pw);
		}

		pw.println("Correct: " + tr);
		return sw.toString();
	}

}
