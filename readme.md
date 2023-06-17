Example code based on example from https://github.com/taurusgroup/multi-party-sig

Note: code in the test directly taken from internal test package from https://github.com/taurusgroup/multi-party-sig

Some of the initial setup steps

```
go mod init gotss/example
go mod tidy
go get github.com/taurusgroup/multi-party-sig@a0b25d3
go mod tidy
```


Needed to pick up the commits with the eth signature
