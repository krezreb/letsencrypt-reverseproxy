build:
	docker pull nginx:stable-alpine
	docker build . -t jbeeson/letsencrypt-reverseproxy

push: build
	docker push jbeeson/letsencrypt-reverseproxy
