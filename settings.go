package main

import (
	mapset "github.com/deckarep/golang-set"
	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"

	"fmt"
)

type Settings struct {
	AllowedTypes mapset.Set `json:"allowedTypes"`
}

// Builds a new Settings instance starting from a validation
// request payload:
// {
//    "request": ...,
//    "settings": {
//		"allowedTypes": [
//			"configMap",
//			"downwardAPI",
//			"emptyDir",
//			"persistentVolumeClaim",
//			"secret",
//			"projected"
//		]
//    }
// }
func NewSettingsFromValidationReq(payload []byte) (Settings, error) {
	return newSettings(
		payload,
		"settings.allowedTypes")
}

// Builds a new Settings instance starting from a Settings
// payload:
// {
//  "settings": {
//		"allowedTypes": [
//			"configMap",
//			"downwardAPI",
//			"emptyDir",
//			"persistentVolumeClaim",
//			"secret",
//			"projected"
//		]
//  }
// }
func NewSettingsFromValidateSettingsPayload(payload []byte) (Settings, error) {
	return newSettings(
		payload,
		"allowedTypes")
}

func newSettings(payload []byte, paths ...string) (Settings, error) {
	if len(paths) != 1 {
		return Settings{}, fmt.Errorf("wrong number of json paths")
	}
	data := gjson.GetManyBytes(payload, paths...)

	allowedTypes := mapset.NewThreadUnsafeSet()

	if data[0].String() == "" {
		// empty settings
		return Settings{
			AllowedTypes: allowedTypes,
		}, nil
	}

	for _, volumeType := range data[0].Array() {
		allowedTypes.Add(volumeType.String())
	}

	return Settings{
		AllowedTypes: allowedTypes,
	}, nil
}

func (s *Settings) Valid() bool {
	if s.AllowedTypes.Contains("*") && (s.AllowedTypes.Cardinality() != 1) {
		return false
	}
	return true
}

func validateSettings(payload []byte) ([]byte, error) {
	logger.Info("validating settings")

	settings, err := NewSettingsFromValidateSettingsPayload(payload)
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(err.Error()))
	}

	if settings.Valid() {
		return kubewarden.AcceptSettings()
	}

	logger.Warn("rejecting settings")
	return kubewarden.RejectSettings(kubewarden.Message("Provided settings are not valid"))
}
