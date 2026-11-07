build:
	docker build . -t jbeeson/letsencrypt-reverseproxy -t jbeeson/letsencrypt-reverseproxy:`git branch --show-current`

build_local:
	docker build . -t letsencrypt-reverseproxy:`git branch --show-current`

push: build
	docker push jbeeson/letsencrypt-reverseproxy

push_branch: build
	docker build . -t jbeeson/letsencrypt-reverseproxy:`git branch --show-current`
	docker push jbeeson/letsencrypt-reverseproxy:`git branch --show-current`

push_test:
	rsync -ardv . $(SSH_TARGET):~/letsencrypt-reverseproxy
	ssh $(SSH_TARGET) bash -c "'cd letsencrypt-reverseproxy && make build'"

run_tests:
	python3 tests/00_certbot.py

BUILD_TIME ?= 04:00
IMAGE_TAG ?= letsencrypt-reverseproxy
UNIT_DIR := $(HOME)/.config/systemd/user
UNIT := letsencrypt-reverseproxy-build
DOCKER := $(shell command -v docker)

setup_scheduled_build:
	@test -n "$(DOCKER)" || { echo "docker not found in PATH"; exit 1; }
	mkdir -p $(UNIT_DIR)
	printf '[Unit]\nDescription=Build $(IMAGE_TAG) image\n\n[Service]\nType=oneshot\nWorkingDirectory=$(CURDIR)\nExecStart=$(DOCKER) build --pull --no-cache -t $(IMAGE_TAG) .\n' > $(UNIT_DIR)/$(UNIT).service
	printf '[Unit]\nDescription=Daily $(IMAGE_TAG) build\n\n[Timer]\nOnCalendar=*-*-* $(BUILD_TIME):00\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n' > $(UNIT_DIR)/$(UNIT).timer
	systemctl --user daemon-reload
	systemctl --user enable --now $(UNIT).timer
	loginctl enable-linger
	systemctl --user list-timers $(UNIT).timer
