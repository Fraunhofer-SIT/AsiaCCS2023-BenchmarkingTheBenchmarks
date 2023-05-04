package de.fraunhofer.sit.eval;

import de.fraunhofer.sit.specifications.attackpatterns.AttackPatternPreset;
import de.fraunhofer.sit.specifications.testcases.TestCase;

class TestCaseInfo {
	public TestCaseInfo(TestCase i, AttackPatternPreset attack) {
		this.testCase = i;
		this.attackPattern = attack;
	}
	public AttackPatternPreset attackPattern;
	public TestCase testCase;
	
	@Override
	public String toString() {
		return "Attack pattern: " + attackPattern + "\nTestcase: " + testCase;
	}
}