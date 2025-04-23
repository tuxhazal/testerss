## How to contribute
- First, fork this repository into your Github account
- Second, clone repository and change to main branch
- Finaly, writing code push and PR to me

## Writing code
I'm checking the quality of code through Codacy when PR/Merge/Push. If you want to consider code quality in advance, please check the link below (not perfect, but very helpful).

https://goreportcard.com/report/github.com/ibrahimsql/aetherxss

e.g: `https://goreportcard.com/report/github.com/{your github account}/aetherxss`

## Build
```
$ go build
```

## Case study
### How to add testing vector of XSS
- Add new vector to https://github.com/ibrahimsql/aetherxss/blob/master/pkg/scanning/payload.go
- Optimize but can affect performance, so please add a general and non-overlapping pattern.

### How to add new entity(e.g event handler)
- Add new pattern to https://github.com/ibrahimsql/aetherxss/blob/master/pkg/scanning/entity.go

### How to add BAV(Basic Another Vulnerability) Patterns
- Add new code to https://github.com/ibrahimsql/aetherxss/blob/master/pkg/scanning/bav.go
- The payload above needs to be defined below.
 + https://github.com/ibrahimsql/aetherxss/blob/master/pkg/scanning/payload.go
- Add Greeping pattern
 + https://github.com/ibrahimsql/aetherxss/blob/master/pkg/scanning/grep.go
- e.g
payload.go
```go
func GetSQLIPayload() []string {
	payload := []string{
		"'",
		"''",
    //... snip ...
		" AND 1=1#",
		" AND 1=0#",
		" ORDER BY 1",
	}
	return payload
}
```

bav.go
```go
//SqliAnalysis is basic check for SQL Injection
func SqliAnalysis(target string, options model.Options) {
	// sqli payload
	bpu, _ := url.Parse(target)
	bpd := bpu.Query()
	var wg sync.WaitGroup
	concurrency := options.Concurrence
	reqs := make(chan *http.Request)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(){
			for req := range reqs {
				SendReq(req, "toGrepping", options)
			}
			wg.Done()
		}()
	}

	for bpk := range bpd {
    // Load payload here!
		for _, sqlipayload := range GetSQLIPayload() {
			turl, _ := optimization.MakeRequestQuery(target, bpk, sqlipayload, "toGrepping", options)
			reqs <- turl
		}
	}
	close(reqs)
	wg.Wait()
}
```

grep.go
```go
//mysql
		"aetherxss-error-mysql1":  "SQL syntax.*?MySQL",
		"aetherxss-error-mysql2":  "Warning.*?mysqli?",
		"aetherxss-error-mysql3":  "MySQLSyntaxErrorException",
		"aetherxss-error-mysql4":  "valid MySQL result",
		"aetherxss-error-mysql5":  "check the manual that (corresponds to|fits) your MySQL server version",
		"aetherxss-error-mysql6":  "check the manual that (corresponds to|fits) your MariaDB server version",
		"aetherxss-error-mysql7":  "check the manual that (corresponds to|fits) your Drizzle server version",
		"aetherxss-error-mysql8":  "Unknown column '[^ ]+' in 'field list'",
		"aetherxss-error-mysql9":  "com\\.mysql\\.jdbc",
		"aetherxss-error-mysql10": "Zend_Db_(Adapter|Statement)_Mysqli_Exception",
		"aetherxss-error-mysql11": "MySqlException",
		"aetherxss-error-mysql12": "Syntax error or access violation",
```
