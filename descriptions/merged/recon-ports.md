# recon-ports

Maps the network surface of a host: which TCP ports are open, what answers on each, and — the real payoff — whether anything other than the main web app is listening. This skill *locates and fingerprints* services and files base URLs as findings; it does not exploit them.

## Dispatch when:

- **You have a bare host or URL and no port map yet.** If all you know is a hostname/IP (and maybe one port from the URL) and no full TCP sweep is recorded, dispatch this. It is the default first move of the network half of recon, and runs in parallel with the web/app recon pass.
- **The target URL names exactly one port and you have not confirmed it is the only one.** `http://10.0.0.5:5000/` is one door; this skill checks the rest of the building.
- **The web app references a backend you cannot see from the front door.** App responses, error pages, or stack traces mention a database (`MySQL`, `PostgreSQL`, `Mongo`, `Redis`), an object/blob store (`S3`, `MinIO`, `bucket`, `presigned URL`), a message broker (`RabbitMQ`, `Kafka`, AMQP), a search engine (`Elasticsearch`, `Solr`), or an internal admin daemon — but no such service has been located. The backend is often co-located and listening.
- **Connection errors or stack traces leak a host:port pair.** Strings like `could not connect to 127.0.0.1:6379`, `Connection refused (localhost:9000)`, `dial tcp :3306`, or `boto3 endpoint http://...:8333` confirm a service to characterise plus anything beside it.
- **A second web port is hinted at.** Redirects, `Location:` headers, hard-coded links, or JS config pointing at `:8080`, `:8443`, `:9001`, `:3000`, or an `/admin` on a different port → map all HTTP listeners.
- **The objective is plausibly somewhere other than the obvious app.** Flags/secrets/data the front-end app clearly does not own (raw dumps, internal dashboards, storage buckets) likely live on a co-located service on an unusual port that only a full sweep reveals.
- **Pivoting after an app dead-ends.** The known web app is hardened or has no obvious bug but the objective is clearly elsewhere — re-run the network pass to surface the other listeners that are the real target.

## Key techniques:

- **Full TCP state sweep.** `nmap -p- <host>`. Any open port that is **not** the URL's port is a lead. A top-100 / common-ports scan misses co-located services; a full `-p-` sweep finds them. Classic pattern: URL says `:5000`, sweep also shows a high port speaking S3/MinIO.
- **Targeted version detection on the open ports only.** Once ports are known, fingerprint just the open ones to tell the planner which specialist to dispatch next (exposed-bucket tester, default-creds tester, CVE check on a banner-leaking daemon). Do not version-probe the whole range.
- **Filtered host → single host-discovery retry.** `nmap -p- <host>` returning `ok=True` with no open ports means the host dropped the probes; one `tcp-syn` retry before concluding "nothing here" is the right escalation — not raising timeouts.

## Recognition tells (request → response):

- **Object store on a high port** → `curl http://<host>:9000/` returns XML like `<ListAllMyBucketsResult>` or `<Error><Code>AccessDenied</Code>`, a `Server: MinIO` header, or `x-amz-request-id`. MinIO console often sits beside it on `:9001`. File the base URL for a bucket/storage specialist.
- **Redis** → `:6379` open, service detection shows `redis`; raw `PING` returns `+PONG`, or `INFO` returns `redis_version:...` with no auth → exposed, often unauthenticated cache.
- **MongoDB** → `:27017` open, detection reports `mongodb`; `mongodb-info` dumps databases with no auth → exposed datastore.
- **MySQL/Postgres** → `:3306` / `:5432` open; detection returns the server version banner (`5.7.x`, `PostgreSQL 1x`) → backend DB to probe for default/weak creds.
- **Second web listener** → `curl http://<host>:8080/` or `nmap_http_enum` returns 200/301 with a `Server:` header distinct from the main app → a whole second app/admin surface to recon.
- **Message broker** → `:5672` (AMQP/RabbitMQ), `:15672` (RabbitMQ management UI, HTTP), `:9092` (Kafka), `:1883` (MQTT) open → exposed broker / management console.

## When NOT to use / easily confused with:

- **Not for working the known web app itself.** Homepage, forms, parameters, directories, cookies, and headers of the main URL belong to the **web/app recon** pass. This skill deliberately skips the app on the URL's port and does not re-report it.
- **Not for exploiting a service it found.** Dumping a bucket, brute-forcing Redis, or testing the second web app's parameters is the next specialist's job. Map, fingerprint, file the finding, stop.
- **Don't confuse host-environment noise with target services.** On localhost/loopback targets the developer machine's own daemons leak onto the address — AirTunes/AirPlay on `5000`/`7000` (`Server: AirTunes`, RTSP banners), a MikroTik bandwidth-test daemon on `49152`. Note these once; do not chase or version-probe them.
- **Don't reach for the heavy scans.** Vuln scripts (`nmap_vuln_scan`) and aggressive scans are slow and stall the rest of recon. This pass is full state sweep + targeted version detection on the open ports only. A pass that finishes and reports the open list beats an exhaustive one that never returns.
- **A single open web port is not automatically a win.** If the full sweep shows *only* the main app's port, the correct output is "confirmed: just the one app" — the value is the confirmation. Do not invent co-located services the scan did not reveal.
- **Not a substitute for app-layer vuln triage.** A reflected value, SQL error, SSTI sink, or IDOR lives in the app's request/response handling and routes to the relevant web-vuln skill. This skill answers only "what is listening on the wire," not "what bug the listener has."
