# Delta change script (a job's CHANGEFILE; runs in the guest as root).
# Request-path benchmark: Docker publishing container ports, the one hop
# firru exposure follows (a published port -> the container behind it).
#   waf      owasp/modsecurity-crs:nginx, published on 8080 (docker-proxy and
#            DNAT), proxying to app over the bridge
#   app      php:7.4-apache (end of life), on the bridge only: reached
#            through waf, not published
#   app-pub  the same image published directly on 8081
# Images from Docker Hub (an egress base); their digests go to the log.
# A request each way, so the connection audit sees the edges.
set -e
export DEBIAN_FRONTEND=noninteractive
bl-apt install -y docker.io curl
docker network create bench
docker run -d --name app --network bench php:7.4-apache
docker run -d --name app-pub -p 8081:80 php:7.4-apache
docker run -d --name waf --network bench -p 8080:8080 -e BACKEND=http://app:80 owasp/modsecurity-crs:nginx
docker image ls --digests
for i in $(seq 1 30); do curl -fsS -o /dev/null http://127.0.0.1:8080/ && break; sleep 2; done
curl -sS -o /dev/null -w 'waf %{http_code}\n' http://127.0.0.1:8080/
curl -sS -o /dev/null -w 'app-pub %{http_code}\n' http://127.0.0.1:8081/
