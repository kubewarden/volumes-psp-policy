package main

import (
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	easyjson "github.com/mailru/easyjson"
)

type Settings struct {
	AllowedTypes mapset.Set[string] `json:"allowedTypes"`
}

func NewSettingsFromRaw(rawSettings *RawSettings) Settings {
	allowedTypes := mapset.NewThreadUnsafeSet[string](rawSettings.AllowedTypes...)

	return Settings{
		AllowedTypes: allowedTypes,
	}
}

// Builds a new Settings instance starting from a validation
// request payload:
//
//	{
//	   "request": ...,
//	   "settings": {
//			"allowedTypes": [
//				"configMap",
//				"downwardAPI",
//				"emptyDir",
//				"persistentVolumeClaim",
//				"secret",
//				"projected"
//			]
//	   }
//	}
func NewSettingsFromValidationReq(payload []byte) (Settings, error) {
	settingsJson := gjson.GetBytes(payload, "settings")

	rawSettings := RawSettings{}
	err := easyjson.Unmarshal([]byte(settingsJson.Raw), &rawSettings)
	if err != nil {
		return Settings{}, err
	}

	return NewSettingsFromRaw(&rawSettings), nil
}

// Builds a new Settings instance starting from a Settings
// payload:
//
//	{
//		  "allowedTypes": [
//		  	"configMap",
//		  	"downwardAPI",
//		  	"emptyDir",
//		  	"persistentVolumeClaim",
//		  	"secret",
//		  	"projected"
//		  ]
//	}
func NewSettingsFromValidateSettingsPayload(payload []byte) (Settings, error) {
	rawSettings := RawSettings{}
	err := easyjson.Unmarshal(payload, &rawSettings)
	if err != nil {
		return Settings{}, err
	}

	return NewSettingsFromRaw(&rawSettings), nil
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
