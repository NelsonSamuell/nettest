# Linux hosts only.
#
# On macOS and Windows, Docker runs inside a virtual machine, so --net=host
# attaches to the VM's network rather than the real LAN and every result
# describes a network that does not exist. netcheck detects containerisation and
# refuses active checks when the default route is a virtual adapter.
#
#   docker build -t netcheck .
#   docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN netcheck doctor

FROM python:3.13-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 libcap2-bin \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pyproject.toml README.md ./
COPY netcheck ./netcheck
RUN pip install --no-cache-dir .

ENTRYPOINT ["netcheck"]
CMD ["doctor"]
