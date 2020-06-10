FROM alpine:3.10

ARG ANSIBLE_VERSION=2.8.5
ARG VERSION
ENV VERSION=${VERSION}
ENV WORKSPACE_PATH=/workspace
ENV BASE_PATH=/file-crypt
ENV ANSIBLE_PATH=${BASE_PATH}/ansible

RUN mkdir -p /etc/ansible

COPY ansible.cfg /etc/ansible/ansible.cfg
COPY ansible ${ANSIBLE_PATH}

RUN apk add --no-cache bash bash-completion ca-certificates python3 python3-dev build-base libffi-dev vim jq openssl openssl-dev openssh-client && \
    ln -s /usr/bin/python3 /usr/bin/python && \
    pip3 install --upgrade pip && \
    pip3 install cffi && \
    pip3 install ansible==${ANSIBLE_VERSION} requests jmespath ansible-modules-hashivault && \
    pip3 install jinja2 pycryptodome

WORKDIR ${WORKSPACE_PATH}
ENTRYPOINT ["/bin/bash"]
