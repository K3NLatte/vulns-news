package processor

import "encoding/json"

var screeningSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["relevance", "reason", "evidence_ids"],
  "properties": {
    "relevance": {
      "type": "string",
      "enum": ["related", "possibly_related", "unrelated", "unknown"]
    },
    "reason": {"type": "string", "minLength": 1},
    "evidence_ids": {
      "type": "array",
      "minItems": 1,
      "uniqueItems": true,
      "items": {"type": "string", "minLength": 1}
    }
  }
}`)

var deepAnalysisSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "summary",
    "repository_impact",
    "missing_information",
    "recommended_actions"
  ],
  "properties": {
    "summary": {"$ref": "#/$defs/supported_claim"},
    "repository_impact": {"$ref": "#/$defs/supported_claim"},
    "missing_information": {
      "type": "array",
      "items": {"type": "string", "minLength": 1}
    },
    "recommended_actions": {
      "type": "array",
      "minItems": 1,
      "items": {"type": "string", "minLength": 1}
    }
  },
  "$defs": {
    "supported_claim": {
      "type": "object",
      "additionalProperties": false,
      "required": ["text", "evidence_ids"],
      "properties": {
        "text": {"type": "string", "minLength": 1},
        "evidence_ids": {
          "type": "array",
          "minItems": 1,
          "uniqueItems": true,
          "items": {"type": "string", "minLength": 1}
        }
      }
    }
  }
}`)

// ScreeningSchema returns a copy of the schema sent to and used to validate the
// local model's screening response.
func ScreeningSchema() json.RawMessage {
	return append(json.RawMessage(nil), screeningSchema...)
}

// DeepAnalysisSchema returns a copy of the schema sent to and used to validate
// the local model's detailed response.
func DeepAnalysisSchema() json.RawMessage {
	return append(json.RawMessage(nil), deepAnalysisSchema...)
}
