DOCKERFILE := Dockerfile
REPOSITORY := openshiftio/fabric8-analytics-cvejob

REGISTRY := quay.io
DEFAULT_TAG=latest


.PHONY=docker-build

all: prep docker-build

prep: build-cpe2pkg python-package-names build-maven-packages javascript-package-names java-package-names

build-cpe2pkg:
	cd tools/src/cpe2pkg/ &&\
	mvn clean verify
	cp tools/src/cpe2pkg/target/cpe2pkg.jar tools/bin/cpe2pkg.jar

build-maven-packages:
	cd tools/src/maven-packages/ &&\
	mvn clean verify
	cp tools/src/maven-packages/target/maven-packages.jar tools/bin/maven-packages.jar

python-package-names:
	python3.6 scripts/get_python_packages.py > data/python-packages

javascript-package-names:
	scripts/get_javascript_packages.sh > data/javascript-packages

java-package-names: build-maven-packages
	scripts/get_java_packages.sh > data/java-packages

test:
	./qa/run-tests.sh

docker-build:
	docker build --no-cache -t $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG) -f $(DOCKERFILE) .
	@echo $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG)

fast-docker-build:
	docker build -t $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG) -f $(DOCKERFILE) .
	@echo $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG)

get-image-name:
	@echo $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG)

get-image-repository:
	@echo $(REPOSITORY)

get-push-registry:
	@echo $(REGISTRY)

clean:
	-rm -rf database/ .external/ data/*-packages tools/bin/*.jar
