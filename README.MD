# Repository overview
This repostitory contains the code of the AsiaCCS 2023 submission "Benchmarking the Benchmarks".

# Code
The Code folder contains the necessary code to rerun the evaluation.

## Input
Contains benchmark test suites as provided by the test suite providers such as NIST.
Note that for copyright reasons you need to fill these folders manually.
```Code/Input/Juliet``` should contain the code of Juliet v. 1.3 available from [NIST](https://samate.nist.gov/SARD/test-suites/111).
```Code/Input/BenchmarkJava/``` should contain the code of [OWASP](https://github.com/OWASP-Benchmark/BenchmarkJava)

## Prepare
Migrates servlets from javax.servlet (old namespace) to jakarta.servlet (new namespace).
Also generates web.xml files for Servlet test cases.

## CreateSpecification
Creates the ```Models.xml``` file in the Output folder. The ```Models.xml``` file specifies the behavior of each test case. In an ideal world, such as specification would be written by the test case author.

## CreateExploits
Takes the ```Models.xml``` and ```Presets.xml``` from the Output folder and creates exploit Java files.

## RunExploits
Contains code used to start servlet containers and to create the environment the exploit should work in.

## Eval
Evaluates the outputs from the docker containers.

## Native
Contains source code to generate a native Exploit native JNI *.so file.
