package ffu

import (
	"bytes"
	"fmt"
)

func requireCanonicalDEROrder(values []derValue, label string) error {
	for index := 1; index < len(values); index++ {
		if bytes.Compare(values[index-1].full, values[index].full) > 0 {
			return fmt.Errorf("%s is not in canonical DER SET order", label)
		}
	}
	return nil
}
