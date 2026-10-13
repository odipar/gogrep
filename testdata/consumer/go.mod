module example.com/repogrep

go 1.26.0

require github.com/odipar/gogrep v0.0.0-00010101000000-000000000000

require gopkg.in/yaml.v3 v3.0.1 // indirect

// CI drops this replace and gets the commit under test from a module proxy
// that testdata/modzip fills: see .github/workflows/test.yml.
replace github.com/odipar/gogrep => ../..
