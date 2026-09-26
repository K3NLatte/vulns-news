package processor

import (
	"encoding/json"
	"fmt"
)

// savedScreeningSchema preserves checkpoint validation independently of the model wire format.
var savedScreeningSchema = json.RawMessage(`{
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

// Cardinality across domains is checked semantically so citation failures remain
// eligible for the bounded correction retry.
var screeningSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["relevance", "reason", "advisory_evidence_ids", "repository_evidence_ids"],
  "properties": {
    "relevance": {"type": "string", "enum": ["related", "possibly_related", "unrelated", "unknown"]},
    "reason": {"type": "string", "minLength": 1},
    "advisory_evidence_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "minLength": 1}},
    "repository_evidence_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "minLength": 1}}
  }
}`)

func screeningSchemaWithEvidenceIDs(evidence []Evidence) (json.RawMessage, error) {
	var advisory, repository []Evidence
	for _, item := range evidence {
		switch item.Kind {
		case EvidenceNVD, EvidenceAdvisory:
			advisory = append(advisory, item)
		case EvidenceRepositoryDependency, EvidenceRepositorySource, EvidenceStaticAnalysis:
			repository = append(repository, item)
		}
	}
	schema, err := schemaWithEvidenceIDs(screeningSchema, advisory, "properties", "advisory_evidence_ids", "items")
	if err != nil {
		return nil, err
	}
	return schemaWithEvidenceIDs(schema, repository, "properties", "repository_evidence_ids", "items")
}

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

// schemaWithEvidenceIDs clones the base schema so concurrent candidates cannot
// share citation enums. Backend validation still checks IDs and evidence kinds.
func schemaWithEvidenceIDs(raw json.RawMessage, evidence []Evidence, path ...string) (json.RawMessage, error) {
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	items := schema
	for _, key := range path {
		next, ok := items[key].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("evidence schema path %q is not an object", key)
		}
		items = next
	}
	ids := make([]string, len(evidence))
	for i, item := range evidence {
		ids[i] = item.ID
	}
	if len(ids) == 0 {
		// An empty enum is not a valid JSON Schema. Reject all items while
		// allowing an empty array when this evidence domain is unavailable.
		items["not"] = map[string]any{}
	} else {
		items["enum"] = ids
	}
	return json.Marshal(schema)
}

// ScreeningSchema returns a copy of the base screening validation schema.
// Model requests additionally constrain citations to the input's evidence IDs.
func ScreeningSchema() json.RawMessage {
	return append(json.RawMessage(nil), screeningSchema...)
}

// DeepAnalysisSchema returns a copy of the base detailed-response schema.
// Model requests additionally constrain citations to the input's evidence IDs.
func DeepAnalysisSchema() json.RawMessage {
	return append(json.RawMessage(nil), deepAnalysisSchema...)
}
