module silkwire/implant

go 1.24.4

require (
	github.com/Ne0nd0g/go-clr v1.0.3
	github.com/aymanbagabas/go-pty v0.2.2
	github.com/kbinani/screenshot v0.0.0-20250624051815-089614a94018
	github.com/mattn/go-sqlite3 v1.14.32
	golang.org/x/sys v0.33.0
	google.golang.org/grpc v1.74.2
	silkwire/proto v0.0.0-00010101000000-000000000000
	silkwire/shared v0.0.0-00010101000000-000000000000
)

require (
	github.com/creack/pty v1.1.21 // indirect
	github.com/gen2brain/shm v0.1.0 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/jezek/xgb v1.1.1 // indirect
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e // indirect
	github.com/praetorian-inc/goffloader v0.0.0-20250222211414-7a1519bb384d // indirect
	github.com/u-root/u-root v0.11.0 // indirect
	golang.org/x/crypto v0.38.0 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250528174236-200df99c418a // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

replace silkwire/proto => ../proto

replace silkwire/shared => ../shared
