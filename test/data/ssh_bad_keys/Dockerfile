FROM alpine:3.20

RUN apk add --no-cache openssh-server && \
    ssh-keygen -A && \
    echo "root:testpassword" | chpasswd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Replace the auto-generated RSA host key with a known-bad one
COPY ssh_host_rsa_key /etc/ssh/ssh_host_rsa_key
RUN chmod 600 /etc/ssh/ssh_host_rsa_key

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
