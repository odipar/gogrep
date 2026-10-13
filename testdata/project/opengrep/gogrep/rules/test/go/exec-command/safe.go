package safe

import "os"

func ok() { os.Getenv("HOME") }
