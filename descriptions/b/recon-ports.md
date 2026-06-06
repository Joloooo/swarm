# recon-ports — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **You have a bare host or URL and no port map yet** → if the only thing you know is a hostname/IP (and maybe one port from the URL), and no full TCP sweep has been recorded, dispatch this. It is the default first move of the network half of recon.
- **The target URL names exactly one port and you have not confirmed it is the only one** → if you see `http://10.0.0.5:5000/` and have only ever touched `:5000`, you have not seen the network surface yet. The given port is one door; this skill checks the rest of the building.
- **The web app references a backend you cannot see from the front door** → if app responses, error pages, or stack traces mention a database (`MySQL`, `PostgreSQL`, `Mongo`, `Redis`), an object/blob store (`S3`, `MinIO`, `bucket`, `presigned URL`), a message broker (`RabbitMQ`, `Kafka`, AMQP), a search engine (`Elasticsearch`, `Solr`), or an internal admin daemon, but no such service has been located on the host → scan for it. The backend is often co-located and listening.
- **Connection errors or stack traces leak a host:port pair** → strings like `could not connect to 127.0.0.1:6379`, `Connection refused (localhost:9000)`, `dial tcp :3306`, or `boto3 endpoint http://...:8333` → that port is a confirmed service to enrich; run the scan to characterise it and anything beside it.
- **A second web port is hinted at** → redirects, `Location:` headers, hard-coded links, or JS config pointing at `:8080`, `:8443`, `:9001`, `:3000`, an `/admin` on a different port → confirms there is more than one HTTP listener; map them all.
- **The objective is plausibly "somewhere other than the obvious app"** → flags/secrets/data that the front-end app clearly does not own (raw dumps, internal dashboards, storage buckets) → the likely home is a co-located service on an unusual port that only a full sweep reveals.
- **You are at the very start of an engagement and want parallel coverage** → while the web/app recon pass works the homepage, forms, and directories, this skill works ports and services in parallel. If app-recon is already running and ports are unmapped, dispatch this beside it.

## Use-case scenarios

- **Black-box first contact.** You are handed only a URL or IP. Before any exploitation, you need the network surface: which TCP ports are open, what answers on each, and — the real payoff — whether anything other than the main web app is listening. This skill owns that pass.
- **Finding the second service.** The single most valuable thing this skill produces is the *co-located* service: an S3-compatible object store on `:8333` or `:9000`, a Redis on `:6379`, a Mongo on `:27017`, a MySQL on `:3306`, a second nginx on `:8080`, an admin panel on a high port. A top-100 or common-ports scan misses these; a full `-p-` sweep finds them. Whenever the challenge feels like it has a hidden backend, this is the move.
- **Confirming the attack/input surface is complete.** Before committing to deep work on the one known web app, you want assurance you are not ignoring an easier or richer target. A full scan either confirms "just the one app" or hands you new base URLs to test.
- **Pivoting after an app dead-ends.** The known web app is hardened or has no obvious bug, but the objective is clearly elsewhere. Re-running the network pass (or reading its findings) surfaces the other listeners that are the real target.
- **Service/version fingerprinting for downstream specialists.** Once ports are known, version detection on the open ones (not the whole range) tells the planner *which* specialist to dispatch next — an exposed-bucket tester for an object store, a default-creds tester for a Redis/Mongo, a CVE check for a banner-leaking daemon.

## Concrete tells (request → response examples)

- **Full TCP state sweep** → `nmap -p- <host>` returns `5000/tcp open` *and* `8333/tcp open` (or `9000`, `6379`, `27017`, `3306`, `8080`). Any open port that is **not** the URL's port is a lead. The classic pattern: the URL says `:5000`, the sweep also shows a high port speaking S3/MinIO.
- **Object store on a high port** → `curl http://<host>:9000/` returns XML like `<ListAllMyBucketsResult>` / `<Error><Code>AccessDenied</Code>`, or a `Server: MinIO` header, or `x-amz-request-id`. MinIO console often sits beside it on `:9001`. → file the base URL, hand to a bucket/storage specialist.
- **Redis** → banner/`nmap_service_detection` on `:6379` shows `redis`; a raw `PING` returns `+PONG`, or `INFO` returns `redis_version:...` with no auth. → exposed cache, often unauthenticated.
- **MongoDB** → `:27017` open, service detection reports `mongodb`; `nmap_default_scripts` runs `mongodb-info` and dumps databases with no auth. → exposed datastore.
- **MySQL/Postgres** → `:3306` / `:5432` open; service detection returns the server version banner (`5.7.x`, `PostgreSQL 1x`). → backend DB to probe for default/weak creds.
- **Second web listener** → `nmap_http_enum` or `curl http://<host>:8080/` returns a 200/301 with an HTTP `Server:` header distinct from the main app. → a whole second app/admin surface to recon.
- **Message broker** → `:5672` (AMQP / RabbitMQ), `:15672` (RabbitMQ management UI — HTTP), `:9092` (Kafka), `:1883` (MQTT) open. → exposed broker / management console.
- **Filtered host** → `nmap -p- <host>` returns `ok=True` with no open ports listed → the host dropped the probes; a single host-discovery retry (`tcp-syn`) before concluding "nothing here" is the right escalation, not raising timeouts.

## When NOT to use it / easily-confused-with

- **Not for working the known web app itself.** The homepage, forms, parameters, directories, cookies, and headers of the main URL belong to the **web/app recon** pass, not here. This skill deliberately skips the app on the URL's port and does not re-report it. If the question is "what does the front page do / what endpoints exist on the main app," that is app-recon, not port-recon.
- **Not for exploiting a service it found.** This skill *locates and fingerprints*; it hands off base URLs as findings. Actually dumping a bucket, brute-forcing Redis, or testing the second web app's parameters is the next specialist's job. Map, fingerprint, file the finding, stop.
- **Don't confuse host-environment noise with target services.** On localhost/loopback benchmarks the developer machine's own daemons leak onto the address — AirTunes/AirPlay on `5000`/`7000` (`Server: AirTunes`, RTSP banners), a MikroTik bandwidth-test daemon on `49152`. These are host noise, not the target; note them once and do not chase them as leads or version-probe them.
- **Don't reach for the heavy scans here.** Vuln scripts (`nmap_vuln_scan`) and aggressive scans are slow and stall the rest of recon. This pass is "full state sweep + targeted version detection on the open ports only." A pass that finishes and reports the open list is worth far more than an exhaustive one that never returns.
- **A single open web port is not automatically this skill's win.** If the full sweep shows *only* the main app's port and nothing else, the right output is "confirmed: just the one app" — the value was the confirmation, not a finding. Do not invent co-located services that the scan did not reveal.
- **Not a substitute for app-layer vuln triage.** A reflected value, a SQL error, an SSTI sink, or an IDOR all live in the app's request/response handling and route to the relevant web-vuln skill. This skill answers only "what is listening on the wire," not "what bug does the listener have."

B:recon-ports done

