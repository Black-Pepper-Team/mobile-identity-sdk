set -e

go get -u golang.org/x/mobile/bind

gomobile bind -target ios -o ./Frameworks/Identity.xcframework
