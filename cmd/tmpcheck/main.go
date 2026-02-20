package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"provid-backend/internal/model/webrequest"
)

func main() {
	b, _ := io.ReadAll(os.Stdin)
	var r webrequest.CreateSegmenRequest
	if err := json.Unmarshal(b, &r); err != nil {
		panic(err)
	}
	fmt.Printf("raw=%s\n", string(r.IsActiveRaw))
	fmt.Printf("parsed=%v\n", r.GetIsActiveOrDefault(true))
}
