---
title: "In-band Task Provisioning for DAP"
category: info

docname: draft-wang-ppm-dap-taskprov-latest
submissiontype: IETF  # also: "independent", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Privacy Preserving Measurement"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: "Privacy Preserving Measurement"
  type: "Working Group"
  mail: "ppm@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/ppm/"
  github: "wangshan/draft-wang-ppm-dap-taskprov"
  latest: "https://wangshan.github.io/draft-wang-ppm-dap-taskprov/draft-wang-ppm-dap-taskprov.html"

author:
 -
    fullname: Shan Wang
    organization: Apple Inc.
    email: "shan_wang@apple.com"
 -
    fullname: Christopher Patton
    organization: Cloudflare
    email: "chrispatton+ietf@gmail.com"

normative:

informative:


--- abstract

An extension for the Distributed Aggregation Protocol (DAP) is specified that
allows the task configuration to be provisioned in-band.


--- middle

# Introduction

The DAP protocol {{?DAP=I-D.draft-ietf-ppm-dap-01}} enables secure aggregation
of a set of reports submitted by clients. This process is centered around a
"task" that determines, among other things, the cryptographic scheme to use for
the secure computation (a Verifiable Distributed Aggregation Function
{{?VDAF=I-D.draft-irtf-cfrg-vdaf-01}}), how reports are partitioned into
batches, and privacy parameters such as the minumum size of each batch.

The core DAP specifcation does not define a mechanism for provisioning task
configurations to the various parties (i.e., the clients, aggregators, and the
collector). Thus it is up to each deployment of DAP to securely implement its
own mechanism.

This document describes a mechanism for configuring tasks that may be useful in
many deployments. The goal of this mechanism is to define a task provision
method that utilizes just the upload channel and the metadata in the `Report`
itself.

At a high level, this extension asks client to include all the task
configuration parameters it received out-of-band from task author, in the
extension field of the `Report` it uploads to aggregators. The aggregators will
create a DAP task upon receiving `Report` with such extension (or `ReportShare`
in the case of helper.)

By defining this mechanism as an extension, we can guarantee that for any
deployments implementing this extension, all information required for
aggregating a report is included in the report itself. There is no need for
out-of-band task orchestration between leader and helpers, therefore making
adoption of DAP easier. Since aggregators must create tasks using the same
parameters client sent, this extension prevents task authors from giving clients
and aggregators different task parameters in order to achieve reduced privacy
guarantee, without requiring an out-of-band mechanism.

This extension affects upload, aggregate and collect sub-protocols.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Similar to {{?DAP=I-D.draft-ietf-ppm-dap-01}}, this document uses the verbs
"abort" and "alert with `[some error message]`" to describe how protocol
participants react to various error conditions.

The terms used follow those described in {{?DAP=I-D.draft-ietf-ppm-dap-01}}. The
following new terms are used:

Task provisioning:
: The process of creating a DAP task.

Task configuration:
: The non-secret parameters required to create a task in task provision.

Task author:
: The entity that defines the parameters of a task.


# The "task-prov" Extension

> NOTE(cjpatton) It will be useful to think of a good name for this. Something
> succinct and descriptive is ideal. `task-prov` is fine, but we can maybe do
> better.

A new extension is defined:

~~~
enum {
    task-prov(0xff00),
    (65535)
} ExtensionType;
~~~
> NOTE(shan) TLS uses underscore `_` to define codepoints, which is different
> from DAP's convension of using hyphen `-`, which one to follow?
> See [#314](ietf-wg-ppm/draft-ietf-ppm-dap#314) for discussion.

When the Client includes this extension with its report, the body of the
extension is structured as follows:

~~~
struct {
    /* Info specific for a task. */
    opaque task_info<1..2^8-1>;

    /* A list of URLs relative to which an aggregator's API endpoints
    can be found. Defined in I-D.draft-ietf-ppm-dap-02. */
    Url aggregator_endpoints<1..2^16-1>;

    /* This determines the query type for batch selection and the
    properties that all batches for this task must have. Defined in
    I-D.draft-ietf-ppm-dap-02. */
    QueryConfig query_config;

    /* The maximum number of times a batch of reports may be queried by
    the Collector. */
    uint16 max_batch_lifetime;

    /* Time up to which Clients are allowed to upload to this task. See
    https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/pull/304. Defined
    in I-D.draft-ietf-ppm-dap-02. */
    Time task_expiration;

    /* A codepoint defined in I-D.draft-irtf-cfrg-vdaf-03 or reserved
    for private use. */
    VdafType vdaf_type;

    /* Additional parameters relevant for the vdaf_type. */
    opaque vdaf_config<1..2^16-1>;
} TaskConfig;

struct {
    QueryType query_type;    // Defined in I-D.draft-ietf-ppm-dap-02
    Duration time_precision; // Defined in I-D.draft-ietf-ppm-dap-02
    uint32 min_batch_size;
    select (query_type) {
        case time-interval: Empty;
        case fixed-size:     uint32 max_batch_size;
    }
} QueryConfig;
~~~

The purpose of `TaskConfig` is to define all parameters that are necessary
for configuring an aggregator. It includes all the fields to be
associated with a task (see task configuration in
{{?DAP=I-D.draft-ietf-ppm-dap-01}}.). Besides, `TaskConfig` also includes fields
that useful for configuring a task in-band:

* An opaque `task_info` that is specific to a task. For e.g. this can be a
  string describing the purpose of this task.

* An opaque `vdaf_config` that contains any VDAF specific parameters for the
  chosen `vdaf_type`.

The codepoints for standardized (V)DAFs are listed below:

~~~
/* Codepoint for each standardized VDAF. Defined in
 I-D.draft-irtf-cfrg-vdaf-03. */
enum {
    prio3-aes128-count(0x00000000),
    prio3-aes128-sum(0x00000001),
    prio3-aes128-histogram(0x00000002),
    poplar1-aes128(0x00001000),
    (2^32-1)
} VdafType;
~~~

The structure of the `vdaf_config` field is not specified in this document,
instead it needs to be defined by the VDAF itself. For VDAFs specified
in {{?VDAF=I-D.draft-irtf-cfrg-vdaf-01}}, implementations SHOULD use the
following structure:

~~~
struct {
    select (vdaf_type) {
        case prio3-aes128-count: Empty;
        case prio3-aes128-sum: uint8 bits;
        case prio3-aes128-histogram: uint64 buckets<8, 2^24-8>;
        case poplar1-aes128: uint16 bits;
    }
} VdafConfig;
~~~

> OPEN ISSUE: Should DP parameters be defined as a different "dimension" to
> VDAF, given that it's likely various DP mechanisms can be applied to any VDAF.
> See issue [#94](https://github.com/cfrg/draft-irtf-cfrg-vdaf/issues/94) for
> discussion.

The definition of Time, Duration, Url, QueryType follow those in
{{?DAP=I-D.draft-ietf-ppm-dap-01}}.

## Out-of-band parameters {#out-of-band-parameters}

Note that `TaskConfig` does not encode all of the parameters required for the
aggregator to run a task. In particular, parameters that should not be known to
clients, like the VDAF verification key, the collector HPKE configuration, and
whatever assets are required for HTTP request authentication are still
established out-of-band.

> OPEN ISSUE: VDAF verification key needs to be unique per task, spell out
> derivation of it.

# Client Behavior

The client should know whether `task-prov` extension will be used and all
parameters required for `TaskConfig` prior to constructing the extension
body, either out-of-band from aggregators, or from information already saved on
client.

To offer the `task-prov` extension, the client adds the `TaskConfig` structure
it received from the task author in the extensions field of its `Report`. It
computes the task ID as described in {{construct-task-id}}.

## Construct task ID {#construct-task-id}

For `task-prov` extension, a DAP task is not created before distributing task
configuration to clients. Therefore, clients, aggregators and collector
construct the DAP task ID prior to uploading. A DAP task ID is computed as
follows:

~~~
task_id = SHA-256(task_config)
~~~

# Provisioning a task {#provisioning-a-task}

Upon receiving the payload containing extension, leader and helpers perform
similar steps to provision a task.

If aggregator supports `task-prov` extension, it should first check if the
task ID already exists, if so the aggregator continues to the rest of the flow
being processed. Note if the existing tasks's configuration is different from
the one in extension, HPKE decryption will fail due to mismatched AAD.

If the task ID has not been seen before, aggregator should read and decode
`extension_data` with the `TaskConfig` schema. If the decoding failed, it MUST
abort the sub protocol with error "unrecognizedMessage".

If the decoding succeeds, aggregator creates a new task using the task ID
from the decoded extension, and save task configuration with the newly created
task. In particular, aggregator should deserialize `vdaf_config` corresponding
to `vdaf_type`, and pass the relevant parameters to the VDAF initializer. At
this point, the task provision step has completed.

# Leader Behavior

Leader should have saved any parameters described in {{out-of-band-parameters}}.
Leader may not know the task ID of the current task before receiving the first
upload request.

## Change to upload sub-protocol

Upon receiving a report, leader reads the extension codepoint in
`extension_type`. If the leader does not support this extension, it MUST ignore
it. In particular, if the task ID is not known, then it MUST abort the handshake
with "unrecognizedTask".

> See [#334](https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/issues/334) for
> discussion.

If aggregator supports `task-prov` extension, it should proceed to
{{provisioning-a-task}}. If task provision failed, leader MUST alert the client
with error from {{provisioning-a-task}}. If task provision succeeded, leader
should continue to the rest of upload flow.

Leader MAY return error to the client if task creation failed.

## Change to collect sub-protocol

During collect init, leader must perform batch validation (see batch-validation
in {{?DAP=I-D.draft-ietf-ppm-dap-01}}) to the `CollectReq`. This requires leader
to know the parameters associated with the DAP task. However, upon receipt of
`CollectReq`, leader may not know the parameters if the first upload has not
arrived yet. In this case the leader MAY respond with HTTP status code 404
Not Found and an error of type `unrecognizedTask`. The response MAY include a
Retry-After header field to suggest a pulling interval to the collector.

> OPEN ISSUE: Alternatively the leader can just response with 303 and continue
> waiting.

# Helper Behavior

Helper should have saved any parameters described in {{out-of-band-parameters}}.
Similar to leader, helper may not know the task ID of the current task before
receiving the first `AggregateInitializeReq` message from the leader.

## Change to helper aggregate sub-protocol

Upon receipt of a `AggregateInitializeReq`, helper reads the extension
codepoint in `extension_type`. If helper does not support this extension, it
MUST ignore it. If the task ID is not known, then it MUST abort the aggregate
protocol and alert the leader with error "unrecognizedTask".

If helper supports `task-prov` extension, it should proceed to
{{provisioning-a-task}}. If task provision failed, helper MUST alert the leader
with error from {{provisioning-a-task}}. If task provision succeeded, helper
should continue to the rest of helper initialization.

# Collector Behavior

If Collector supports `task-prov` extension and receives a HTTP status code
404 Not Found with error type `unrecognizedTask` after sending a `CollectReq`,
it SHOULD retry with the same `CollectReq`, potentially using an interval from
the Retry-After header in the received response.

# Implementation and Operational Considerations

> OPEN ISSUE: This mechanism brings added overhead in `Report` and `ReportShare`
> since more duplicated data is passed around. Some optimisation can be done in
> the core protocol to reduce this overhead.

# Security Considerations

> NOTE(cjpatton) In this section we would describe any security goals we have
> that go beyond the core DAP spec. We will also discuss if/how the extension
> impacts the security of DAP itself.

A "task" now means the same task ID and same task configuration, if a malicious
client changes the task ID or task configuration, its report will be aggregated
in a different task, with other poison reports from the same malicious attack.
The "good" reports will not be polluted.

# IANA Considerations

> NOTE(cjpatton) Eventually we'll have IANA considerations (at the very least
> we'll need to allocate a codepoint) but we can leave this blank for now.


--- back

# Acknowledgments
{:numbered="false"}

> NOTE(cjpatton) It's a good idea to acknowledge anyone by name who contributed
> to the spec in some way, either directly or indirectly.
> NOTE(shan) Will add more in future commits.

Contributors

Junye Chen
Apple Inc.
junyec@apple.com

Michael Scaria
Apple Inc.
mscaria@apple.com

Suman Ganta
Apple Inc.
sganta2@apple.com

Christopher A. Wood
Cloudflare
caw@heapingbits.net

Kunal Talwar
Apple Inc.
ktalwar@apple.com
