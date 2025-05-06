package gtp2ie

import (
	"fmt"
	"github.com/vagabundor/gtp2json/config"
)

// APNRestrictionLevels maps the APN Restriction levels to their descriptions
var APNRestrictionLevels = map[uint8]string{
	0: "No Existing Contexts or Restriction",
	1: "Public-1",
	2: "Public-2",
	3: "Private-1",
	4: "Private-2",
}

// DecodeAPNRestriction decodes the APN Restriction from the IE content
func DecodeAPNRestriction(content []byte) (interface{}, error) {
	if len(content) < 1 {
		return nil, fmt.Errorf("APN Restriction data is too short")
	}

	restrictionLevel := content[0]
	description, exists := APNRestrictionLevels[restrictionLevel]
	if !exists {
		return nil, fmt.Errorf("unknown APN Restriction level: %d", restrictionLevel)
	}

	switch config.GetOutputFormat() {
	case "numeric":
		return restrictionLevel, nil
	case "text":
		return description, nil
	case "mixed":
		return fmt.Sprintf("%s (%d)", description, restrictionLevel), nil
	default:
		return description, nil
	}
}
