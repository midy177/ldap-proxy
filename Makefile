# 从 git commit 获取版本信息
GIT_COMMIT := $(shell git rev-parse --short=8 HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date +'%Y-%m-%d %H:%M:%S')

# 项目基本信息
PACKAGE_NAME = ldap-proxy
FULL_VERSION = $(GIT_COMMIT)

# 默认目标
all: docker

# 显示版本信息（用于调试）
version:
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Full Version: $(FULL_VERSION)"
	@echo "Build Time: $(BUILD_TIME)"

.PHONY: all docker

docker:
	docker buildx build --platform linux/amd64,linux/arm64 -t 1228022817/$(PACKAGE_NAME):$(FULL_VERSION) . --push