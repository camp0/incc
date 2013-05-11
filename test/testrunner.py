from unittest import TestResult
import sys, time, re

class _BasicTestResult(TestResult):
    """Test result similar to unittest module _TextTestResult"""

    separator1 = '=' * 77
    separator2 = '-' * 77

    def __init__(self, stream, iterations):
        TestResult.__init__(self)
        self.stream = stream
        self.iterations = iterations > 1

    def getDescription(self, test):
        desc=test.shortDescription()
        func=str(test)
        match=re.search("test_(.*) \(.*\.test_(.*)_.*\)", func)
        if not match: return desc or func
        else: return "%2d.%3d: %-67s" % (int(match.group(2)), int(match.group(1)), desc)

    def startTest(self, test):
        TestResult.startTest(self, test)
        if not self.iterations:
            self.stream.write("%-75s" % self.getDescription(test))

    def addSuccess(self, test):
        TestResult.addSuccess(self, test)
        if not self.iterations:
            self.stream.write("ok\n")

    def addError(self, test, err):
        TestResult.addError(self, test, err)
        if not self.iterations:
            self.stream.write("ERR\n")

    def addFailure(self, test, err):
        TestResult.addFailure(self, test, err)
        if not self.iterations:
            self.stream.write("FAIL\n")

    def printErrors(self):
        if not self.iterations:
            self.printErrorList('ERROR', self.errors)
            self.printErrorList('FAIL', self.failures)

    def printErrorList(self, flavour, errors):
        for test, err in errors:
            self.stream.write("\n"+self.separator1+"\n")
            self.stream.write("%s: %s\n" % (flavour,self.getDescription(test)))
            self.stream.write(self.separator2+"\n")
            self.stream.write("%s\n" % err)


class BasicTestRunner:
    """Test runner similar to unittest TextTestRunner"""

    def __init__(self, stream=sys.stderr, iterations=1):

        try: iterations=int(iterations)
        except: iterations=1

        self.stream = stream
        self.iterations = iterations

    def _makeResult(self):
        return _BasicTestResult(self.stream, self.iterations)

    def run(self, test):
        "Run the given test case or test suite."
        result = self._makeResult()
        startTime = time.time()

        # test execution
        for i in range(self.iterations):
            if self.stream == sys.stderr:
                self.stream.write("Iteration:%6d\r" % (i+1))
            test(result)
        if self.stream == sys.stderr: self.stream.write("\n")


        stopTime = time.time()
        timeTaken = stopTime - startTime
        result.printErrors()
        if not self.iterations > 1: self.stream.write(result.separator2+"\n")
        run = result.testsRun
        self.stream.write("Ran %d test%s in %.3fs\n" %
                            (run, run != 1 and "s" or "", timeTaken))
        self.stream.write("\n")
        if not result.wasSuccessful():
            self.stream.write("FAILED (")
            failed, errored = map(len, (result.failures, result.errors))
            if failed:
                self.stream.write("failures=%d" % failed)
            if errored:
                if failed: self.stream.write(", ")
                self.stream.write("errors=%d" % errored)
            self.stream.write(")\n")
        else:
            self.stream.write("OK\n")
        return result
