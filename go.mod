module silkwire

go 1.24.4

require (
	github.com/Binject/go-donut v0.0.0-20201215224200-d947cf4d090d
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51
	github.com/peterh/liner v1.2.2
	github.com/reeflective/console v0.1.25
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.9.1
	github.com/stevedomin/termtable v0.0.0-20150929082024-09d29f3fd628
	golang.org/x/term v0.32.0
	google.golang.org/grpc v1.74.2
	gorm.io/driver/sqlite v1.6.0
	gorm.io/gorm v1.30.1
	mvdan.cc/garble v0.14.2
	silkwire/proto v0.0.0-00010101000000-000000000000
	silkwire/shared v0.0.0-00010101000000-000000000000
)

require (
	github.com/Binject/debug v0.0.0-20210312092933-6277045c2fdf // indirect
	github.com/bluekeyes/go-gitdiff v0.8.1 // indirect
	github.com/carapace-sh/carapace v1.7.1 // indirect
	github.com/carapace-sh/carapace-shlex v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/mattn/go-runewidth v0.0.9 // indirect
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	github.com/reeflective/readline v1.1.3 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	golang.org/x/tools v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250528174236-200df99c418a // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	mvdan.cc/sh/v3 v3.7.0 // indirect
)

replace silkwire/proto => ./proto

replace silkwire/shared => ./shared
