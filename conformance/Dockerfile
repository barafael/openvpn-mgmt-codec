FROM alpine:latest
RUN apk add --no-cache openvpn
COPY test-mgmt.ovpn /etc/openvpn/test-mgmt.ovpn
# Ensure Unix line endings regardless of host OS.
RUN printf 'test-password\n' > /etc/openvpn/mgmt-pw.txt
EXPOSE 7505
CMD ["openvpn", "--config", "/etc/openvpn/test-mgmt.ovpn"]
