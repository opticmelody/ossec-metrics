VERSION := $(shell date +%Y.%m.%d)
PATCH   ?= 0
DISTRO  ?= $(shell lsb_release -cs)
OS      :=$(shell uname)

all: deb

build:
	go build -o ossec-metrics cmd/ossec-metrics/main.go

deb: deb_$(OS)

deb_Linux: build
	mkdir -p tmp/usr/bin
	cp -pR lib DEBIAN tmp/
	cp ossec-metrics tmp/usr/bin/
	sed -i "s/VERSION/$(VERSION)/g" tmp/DEBIAN/control
	sed -i "s/PATCH/$(PATCH)/g"     tmp/DEBIAN/control
	sed -i "s/DISTRO/$(DISTRO)/g"   tmp/DEBIAN/control
	chmod -R 0755 tmp/DEBIAN
	chmod -R go-w tmp
	(cd tmp; fakeroot dpkg -b . ../ont-metrichor-adm-$(VERSION)-$(PATCH)~$(DISTRO).deb)

docker:
	docker build --platform linux/amd64 -t ossec_metrics_build:22.04 .

deb_Darwin: docker
#	GOOS=darwin GOARCH=arm64 go build -o ossec-metrics-osx-arm64 cmd/ossec-metrics/main.go
	docker run --platform linux/amd64 -it --rm -v $$(pwd):$$(pwd) -w $$(pwd) ossec_metrics_build:22.04 make
