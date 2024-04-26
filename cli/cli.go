// CLI for testing/exercising the NFSN libdns provider
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/libdns/nfsn"
)

type operation string

const(
	OperationGetRecords = "GetRecords"
)

func (o *operation) String() string {
	return string(*o)
}

func (o *operation) Set(value string) error {
	switch value {
	case OperationGetRecords:
		*o = OperationGetRecords
	default:
		return fmt.Errorf("Unsupported operation %s", value)
	}

	return nil
}

func readApiKey(fp string) (string, error) {
	f, err := os.Open(fp)
	defer f.Close()

	if err != nil {
		return "", err
	}

	apiKey, err := bufio.NewReader(f).ReadString('\n')

	if err != nil {
		return "", err
	}

	return strings.TrimSpace(apiKey), nil
}

func main() {
	var oArg operation
	fArg := flag.String("f", "api_key.txt", "File containing an NFSN API key")
	zArg := flag.String("z", "", "The zone to operate on")
	lArg := flag.String("l", "", "The login to use")
	flag.Var(&oArg, "o", "The operation to perform. Supported values are: GetRecords")
	flag.Parse()

	apiKey, err := readApiKey(*fArg)

	if err != nil {
		fmt.Printf("Encountered error reading API Key: %v\n", err)
		os.Exit(1)
	}

	p := nfsn.Provider{
		Login: *lArg,
		APIKey: apiKey,
	}

	switch oArg {
	case OperationGetRecords:
		fmt.Printf("Fetching records for zone %s in account %s...\n", *zArg, p.Login)

		records, err := p.GetRecords(context.TODO(), *zArg)

		if err != nil {
			fmt.Printf("Encountered error fetching records: %v\n", err)
		}

		fmt.Print("Found records:\n\n")

		for _, r := range records {
			fmt.Printf("%+v\n\n", r)
		}
	}
}
