package report

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/olekukonko/tablewriter"
)

func GenerateReport(scanResult model.Result, options model.Options) {
	fmt.Println(options.AuroraObject.BrightGreen("[ Information ]"))
	fmt.Println("+ Start: " + scanResult.StartTime.String())
	fmt.Println("+ End: " + scanResult.EndTime.String())
	fmt.Println("+ Duration: " + scanResult.Duration.String())

	renderTable(scanResult.Params, options)
	renderPoCTable(scanResult.PoCs, options)
}

func renderTable(params []model.ParamResult, options model.Options) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{
		"Param",
		"Type",
		"Reflected",
		"R-Point",
		"R-Code",
		"Chars",
	})

	for _, v := range params {
		chars := strings.Join(v.Chars, " ")
		reflected := "false"
		if v.Reflected {
			reflected = "true"
		}

		line := []string{
			v.Name,
			v.Type,
			reflected,
			v.ReflectedPoint,
			v.ReflectedCode,
			chars,
		}
		table.Append(line)
	}
	fmt.Println(options.AuroraObject.BrightGreen("\n[ Parameter Analysis ]"))
	table.Render()
}

func renderPoCTable(pocs []model.PoC, options model.Options) {
	pocTable := tablewriter.NewWriter(os.Stdout)
	pocTable.SetHeader([]string{
		"#",
		"Type",
		"Severity",
		"Method",
		"Param",
		"Inject-Type",
		"CWE",
	})

	for i, v := range pocs {
		line := []string{
			"#" + strconv.Itoa(i),
			v.Type,
			v.Severity,
			v.Method,
			v.Param,
			v.InjectType,
			v.CWE,
		}
		pocTable.Append(line)
	}
	fmt.Println(options.AuroraObject.BrightGreen("\n[ XSS PoCs ]"))
	pocTable.Render()
	for i, v := range pocs {
		fmt.Printf("[#%s] %s\n", strconv.Itoa(i), v.Data)
	}
}
