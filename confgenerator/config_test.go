package confgenerator_test

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"

	"github.com/GoogleCloudPlatform/ops-agent/confgenerator"
	yaml "github.com/goccy/go-yaml"
)

const (
	testDir           = "testdata/metrics_prefix"
	inputFileName     = "input.yaml"
	expectedFileName  = "expected-output.yaml"
	outputFileName    = "output.yaml"
	getPrefixTestFile = "get-prefix-test.yaml"
)

// Test SetMetricsPrefix against valid input cases
func TestSetMetricsPrefixWithValidInput(t *testing.T) {
	testDataDir := filepath.Join(testDir, "valid")
	dirs, err := ioutil.ReadDir(testDataDir)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to read dir %v : %v ", testDataDir, err))
	}

	for _, d := range dirs {
		testName := d.Name()
		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			testDir := filepath.Join(testDataDir, testName)
			err := confgenerator.SetMetricsPrefix(testDir, testDir, inputFileName, outputFileName)
			if err != nil {
				t.Fatal(fmt.Errorf("failed to successfully run SetMetricsPrefix against input %v : %v", inputFileName, err))
			}
			// compare actual output and expected output
			res, err := compareResult(testDir, expectedFileName, outputFileName)
			if err != nil {
				t.Fatal(fmt.Errorf("failed to compare expected and actual output : %v", err))
			}
			if !res {
				t.Fatal(fmt.Errorf("expected and actual output are not matching, comparing %v and %v", expectedFileName, outputFileName))
			}
		})
	}

}

// Test SetMetricsPrefix against invalid input cases
func TestSetMetricsPrefixWithInvalidInput(t *testing.T) {
	testDataDir := filepath.Join(testDir, "invalid")
	dirs, err := ioutil.ReadDir(testDataDir)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to read dir %v : %v ", testDataDir, err))
	}

	for _, d := range dirs {
		testName := d.Name()
		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			testDir := filepath.Join(testDataDir, testName)
			expectedErrFile := filepath.Join(testDir, "error.txt")

			testErr := confgenerator.SetMetricsPrefix(testDir, testDir, inputFileName, outputFileName)
			if testErr == nil {
				t.Fatal(fmt.Errorf("expected to get error from %s as in the error file : %s", testName, expectedErrFile))
			}

			expectedErr, err := ioutil.ReadFile(expectedErrFile)
			if err != nil {
				t.Fatal(fmt.Errorf("can't read expected error file: %v\n", expectedErrFile))
			}
			matched, err := regexp.MatchString(string(expectedErr), fmt.Sprint(testErr))
			if err != nil {
				t.Fatal(fmt.Errorf("got error trying to match expected error and actual error. expected : %v, but got : %v\n", string(expectedErr), testErr))
			}
			if !matched {
				t.Fatal(fmt.Errorf("failed to match expected error and actual error. expected : %v, but got : %v \n", string(expectedErr), testErr))
			}
		})
	}
}

func TestGetMetricsPrefixForApp(t *testing.T) {
	supportedApps := confgenerator.GetSupportedApplications()
	testFilePath := filepath.Join(testDir, getPrefixTestFile)
	// test for all the supported apps
	for _, app := range supportedApps {
		prefix, err := confgenerator.GetMetricsPrefixForApp(app, testFilePath)
		if err != nil {
			t.Fatal(fmt.Errorf("got an unexpected error trying to get prefix for app %v : %v", app, err))
		}
		expected := fmt.Sprintf("%s.googleapis.com", app)
		if prefix != expected {
			t.Fatal(fmt.Errorf("expected prefix [%v] and actual prefix [%v] does not match.", expected, prefix))
		}
	}
	// test for an unsupported app
	_, testErr := confgenerator.GetMetricsPrefixForApp("fakeapp", testFilePath)
	exprectedErrRegex := "failed to get prefix for app fakeapp from .*"
	matched, err := regexp.MatchString(exprectedErrRegex, fmt.Sprint(testErr))
	if err != nil {
		t.Fatal(fmt.Errorf("got error trying to match expected error and actual error. expected : %v, actual : %v\n", string(exprectedErrRegex), testErr))
	}
	if !matched {
		t.Fatal(fmt.Errorf("failed to match expected error and actual error. expected : %v, but got : %v \n", string(exprectedErrRegex), testErr))
	}
}

func compareResult(testDir, expectedFile, outputFile string) (bool, error) {
	// compare output and expected output
	expected := make(map[string]string)
	actual := make(map[string]string)

	expectedData, err := ioutil.ReadFile(filepath.Join(testDir, expectedFile))
	if err != nil {
		return false, fmt.Errorf("failed to read expected file : %v", err)
	}
	err = yaml.Unmarshal(expectedData, &expected)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal expectedData %v : %v", expectedData, err)
	}

	actualData, err := ioutil.ReadFile(filepath.Join(testDir, outputFile))
	if err != nil {
		return false, fmt.Errorf("failed to read output file : %v", err)
	}
	err = yaml.Unmarshal(actualData, &actual)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal actualData %v : %v", actualData, err)
	}

	return reflect.DeepEqual(actual, expected), nil
}
