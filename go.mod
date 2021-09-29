module github.com/jhwbarlow/tcp-audit-bpf-eventer

go 1.17

//replace github.com/jhwbarlow/tcp-audit-common => ../tcp-audit-common

require (
	github.com/aquasecurity/libbpfgo v0.1.1
	github.com/google/uuid v1.3.0
	github.com/jhwbarlow/tcp-audit-common v0.0.0-20210928211236-5e6841819533
)

require golang.org/x/sys v0.0.0-20211001092434-39dca1131b70 // indirect
