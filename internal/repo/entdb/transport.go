package entdb

import (
	"fmt"
	"reflect"
	"unsafe"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
)

// TransportFromClient exposes the SDK client's raw transport. The
// dependency is pinned exactly in go.mod, so reading the private field
// is the narrowest way to keep repository queries on the SDK's raw
// node transport when the typed query helpers are insufficient.
func TransportFromClient(client *sdk.DbClient) (sdk.Transport, error) {
	if client == nil {
		return nil, fmt.Errorf("entdb: nil db client")
	}
	v := reflect.ValueOf(client)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return nil, fmt.Errorf("entdb: invalid db client %T", client)
	}
	field := v.Elem().FieldByName("transport")
	if !field.IsValid() {
		return nil, fmt.Errorf("entdb: db client transport field missing")
	}
	if !field.CanAddr() {
		return nil, fmt.Errorf("entdb: db client transport field is not addressable")
	}
	// #nosec G103 -- the SDK exposes sdk.Transport publicly but not through DbClient.
	transport, ok := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface().(sdk.Transport)
	if !ok || transport == nil {
		return nil, fmt.Errorf("entdb: db client transport unavailable")
	}
	return transport, nil
}
