package stuncheck

import (
	"fmt"

	"github.com/oneclickvirt/gostun/model"
)

// CheckType
// Summarize the NAT type
func CheckType() string {
	return checkType(model.NatMappingBehavior, model.NatFilteringBehavior)
}

func checkType(mappingBehavior, filteringBehavior string) string {
	var result string
	if mappingBehavior != "" && filteringBehavior != "" {
		if mappingBehavior == "inconclusive" || filteringBehavior == "inconclusive" {
			result = "Inconclusive"
		} else if mappingBehavior == "endpoint independent (no NAT)" && filteringBehavior == "endpoint independent" {
			result = "Full Cone"
		} else if mappingBehavior == "endpoint independent" && filteringBehavior == "endpoint independent" {
			result = "Full Cone"
		} else if mappingBehavior == "endpoint independent" && filteringBehavior == "address dependent" {
			result = "Restricted Cone"
		} else if mappingBehavior == "endpoint independent" && filteringBehavior == "address and port dependent" {
			result = "Port Restricted Cone"
		} else if mappingBehavior == "address and port dependent" && filteringBehavior == "address and port dependent" {
			result = "Symmetric"
		} else {
			result = fmt.Sprintf("%v[NatMappingBehavior] %v[NatFilteringBehavior]\n", mappingBehavior, filteringBehavior)
		}
	} else {
		result = "Inconclusive"
	}
	return result
}
