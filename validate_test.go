package main

import (
	"encoding/json"
	"testing"

	mapset "github.com/deckarep/golang-set"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
)

func TestEmptySettingsLeadsToRejection(t *testing.T) {
	settings := Settings{}

	payload, err := kubewarden_testing.BuildValidationRequest(
		"test_data/request-pod-no-volumes.json",
		&settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Expected no error, got '%s'", err.Error())
	}

	var response kubewarden_testing.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("got unexpected error '%+v'", err)
	}

	if response.Accepted != false {
		t.Errorf("got unexpected approval")
	}

	expectedError := "No volume type is allowed"
	if response.Message != expectedError {
		t.Errorf("got '%s' instead of '%s'",
			response.Message, expectedError)
	}
}

func TestApproval(t *testing.T) {
	for _, tcase := range []struct {
		name     string
		testData string
		settings Settings
	}{
		{
			name:     "pod without volumes",
			testData: "test_data/request-pod-no-volumes.json",
			settings: Settings{
				AllowedTypes: mapset.NewSetFromSlice([]interface{}{
					"configMap",
					"downwardAPI",
					"emptyDir",
					"persistentVolumeClaim",
					"secret",
					"projected",
				}),
				},
		},
		{
			name:     "bunch of allowed types, some unexistent",
			testData: "test_data/request-pod-volumes.json",
			settings: Settings{
				AllowedTypes: mapset.NewSetFromSlice([]interface{}{
					"hostPath",
					"projected",
					"foo",
				}),
			},
		},
		{
			name:     "all accepted",
			testData: "test_data/request-pod-volumes.json",
			settings: Settings{
				AllowedTypes: mapset.NewSetFromSlice([]interface{}{
					"*",
				}),
			},
		},
	} {
		payload, err := kubewarden_testing.BuildValidationRequest(
			tcase.testData,
			&tcase.settings)
		if err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		responsePayload, err := validate(payload)
		if err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		var response kubewarden_testing.ValidationResponse
		if err := json.Unmarshal(responsePayload, &response); err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		if response.Accepted != true {
			t.Errorf("on test %q, got unexpected rejection", tcase.name)
		}
	}
}

func TestRejection(t *testing.T) {
	for _, tcase := range []struct {
		name     string
		testData string
		settings Settings
		error    string
	}{
		{
			name:     "none accepted, empty AllowedTypes list in settings",
			testData: "test_data/request-pod-volumes.json",
			settings: Settings{
				AllowedTypes: mapset.NewSetFromSlice([]interface{}{}),
			},
			error: "No volume type is allowed",
		},
		{
			name:     "not all types in allowedTypes",
			testData: "test_data/request-pod-volumes.json",
			settings: Settings{
				AllowedTypes: mapset.NewSetFromSlice([]interface{}{
					"secret",
					"configMap",
				}),
			},
			error: "volume 'test-var' of type 'hostPath' is not in the AllowedTypes list;"+
				" volume 'test-var-local-aaa' of type 'hostPath' is not in the AllowedTypes list;"+
				" volume 'kube-api-access-kplj9' of type 'projected' is not in the AllowedTypes list",
		},
	} {
		payload, err := kubewarden_testing.BuildValidationRequest(
			tcase.testData,
			&tcase.settings)
		if err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		responsePayload, err := validate(payload)
		if err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		var response kubewarden_testing.ValidationResponse
		if err := json.Unmarshal(responsePayload, &response); err != nil {
			t.Errorf("on test %q, got unexpected error '%+v'", tcase.name, err)
		}

		if response.Accepted != false {
			t.Errorf("on test %q, got unexpected approval", tcase.name)
		}

		if response.Message != tcase.error {
			t.Errorf("on test %q, got '%s' instead of '%s'",
				tcase.name, response.Message, tcase.error)
		}
	}
}
