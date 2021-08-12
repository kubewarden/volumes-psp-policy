package main

import (
	"testing"
)

func TestParsingSettingsWithAllValuesProvidedFromValidationReq(t *testing.T) {
	request := `
	{
		"request": "doesn't matter here",
		"settings": {
			"allowedTypes": [
				"configMap",
				"downwardAPI",
				"emptyDir",
				"persistentVolumeClaim",
				"secret",
				"projected"
			]
		}
	}
	`
	rawRequest := []byte(request)

	settings, err := NewSettingsFromValidationReq(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	if settings.AllowedTypes[0] != "configMap" ||
		settings.AllowedTypes[1] != "downwardAPI" ||
		settings.AllowedTypes[2] != "emptyDir" ||
		settings.AllowedTypes[3] != "persistentVolumeClaim" ||
		settings.AllowedTypes[4] != "secret" ||
		settings.AllowedTypes[5] != "projected" {
		t.Errorf("Missing value")
	}
}

func TestParsingSettingsWithNoValueProvided(t *testing.T) {
	request := `
	{
		"request": "doesn't matter here",
		"settings": {
		}
	}
	`
	rawRequest := []byte(request)

	settings, err := NewSettingsFromValidationReq(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	if len(settings.AllowedTypes) != 0 {
		t.Errorf("Expected AllowedTypes to be empty")
	}
}

func TestSettingsWithInvalidEntries(t *testing.T) {
	request := `
	{
		"request": "doesn't matter here",
		"settings": {
			"allowedTypes": [
				"configMap",
				"*"
			]
		}
	}
	`
	rawRequest := []byte(request)

	settings, err := NewSettingsFromValidateSettingsPayload(rawRequest)
	if err != nil {
		t.Error("Expected no error, got one")
	}

	if settings.Valid() {
		t.Errorf("Expected Settings reported as not valid")
	}

}

func TestEmptySettingsAreValid(t *testing.T) {
	request := `
	{
		"request": "doesn't matter here",
		"settings": {
			"allowedTypes": []
		}
	}
	`
	rawRequest := []byte(request)

	settings, err := NewSettingsFromValidateSettingsPayload(rawRequest)
	if err != nil {
		t.Errorf("Unexpected error %+v", err)
	}

	if !settings.Valid() {
		t.Errorf("Settings are reported as not valid")
	}
}
