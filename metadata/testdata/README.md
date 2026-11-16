# metadata testdata

The `*.pb` files are serialized `metadata.PolicyData` protobuf messages. They
stand in for policy metadata files read from a filesystem, so the tests can
verify that `CheckValidity()` rejects corrupt data before it reaches the
policy-setting ioctl or an unlock path.

Each fixture contains a zero-filled wrapped key of the correct lengths; only
the field named in the file is made invalid.

To regenerate a fixture, build the corresponding `PolicyData` value (with a
zero-filled wrapped key of `PolicyKeyLen`/`IVLen`/`HMACLen` bytes) and write
`proto.Marshal(data)` into this directory, e.g. from a temporary program under
`cmd/`:

```go
raw, err := proto.Marshal(policy)
if err != nil { /* ... */ }
if err := os.WriteFile(filepath.Join("metadata", "testdata", name), raw, 0644); err != nil { /* ... */ }
```
