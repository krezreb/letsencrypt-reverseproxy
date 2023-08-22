build:
	docker pull nginx:stable-alpine
	docker build . -t jbeeson/letsencrypt-reverseproxy

push: build
	docker push jbeeson/letsencrypt-reverseproxy
	

push_test:
	rsync -ardv . $(SSH_TARGET):~/letsencrypt-reverseproxy
	ssh $(SSH_TARGET) bash -c "'cd letsencrypt-reverseproxy && make build'"
