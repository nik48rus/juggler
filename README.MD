# Juggler

lightweight api key rotation tool

<img src="logo.png" alt="logo" style="width:256px;"/>

## Setting up and how to use
#### environment

| Variable | Description | Required |
| --- | --- | --- |
| JUGGLER_DB_PATH | path to db | false |
| JUGGLER_PASSWORD | password for crypt data | true |

#### add key to db
```bash
./juggler set key value
```

#### get data by key
```bash
./juggler get key
```

## Functions
#### CLI
- [x] save key
- [x] get data by key
- [x] delete key
#### Web & gRPC
- [ ] save key
- [ ] get data by key
- [ ] delete key
#### Product features
- [x] crypt data
- [ ] number of key usages
- [ ] usage limit period
- [ ] issuing keys in random order for each resource

## Build
```bash
go build -o juggler main.go
```
