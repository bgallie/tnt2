module github.com/bgallie/tnt2

go 1.16

replace github.com/bgallie/filters/pem => /home/bga/workplace/src/github.com/bgallie/filters/pem

require (
	github.com/bgallie/filters/ascii85 v0.0.0-20210616200048-3716ccc6da1a
	github.com/bgallie/filters/flate v0.0.0-20210616200048-3716ccc6da1a
	github.com/bgallie/filters/lines v0.0.0-20210616200048-3716ccc6da1a
	github.com/bgallie/filters/pem v0.0.0-20210617152519-2b00a88fefaf
	github.com/bgallie/tntengine v1.1.1
	golang.org/x/crypto v0.0.0-20210616213533-5ff15b29337e
)
