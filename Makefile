GIT_VERSION := $(shell git describe --tags --abbrev=0 --always)
AUTHOR="davidliyutong"
DEV_AUTHOR="core.harbor.speit.site/oauth2proxy"
PROJECT_NAME="oauth2proxy"

build.docker.buildx:
	docker buildx build --platform=linux/amd64,linux/arm64 -t ${AUTHOR}/${PROJECT_NAME}:${GIT_VERSION} -t ${AUTHOR}/${PROJECT_NAME}:latest -f manifests/docker/Dockerfile .
	docker buildx build --load -t ${AUTHOR}/${PROJECT_NAME}:latest -f manifests/docker/Dockerfile .

push.docker.buildx:
	docker buildx build --push --platform=linux/amd64,linux/arm64 -t ${AUTHOR}/${PROJECT_NAME}:${GIT_VERSION} -t ${AUTHOR}/${PROJECT_NAME}:latest -f manifests/docker/Dockerfile .
