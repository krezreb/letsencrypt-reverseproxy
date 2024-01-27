build:
	docker pull nginx:stable-alpine
	docker build . -t jbeeson/letsencrypt-reverseproxy -t jbeeson/letsencrypt-reverseproxy:`git branch --show-current`

push: build
	docker push jbeeson/letsencrypt-reverseproxy

push_branch: build
	docker build . -t jbeeson/letsencrypt-reverseproxy:`git branch --show-current`
	docker push jbeeson/letsencrypt-reverseproxy:`git branch --show-current`


push_test:
	rsync -ardv . $(SSH_TARGET):~/letsencrypt-reverseproxy
	ssh $(SSH_TARGET) bash -c "'cd letsencrypt-reverseproxy && make build'"
