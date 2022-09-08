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
many deployments. The goal of this mechanism is to add transparency to the
task provision process, and define a task provision method that does not rely
on deployment specific leader-helper out-of-band agreement.

At a high level, this extension asks client to include all the task
configuration parameters it received out-of-band from task author, in the
extension field of the `Report` it uploads to aggregators. The aggregators will
create a DAP task upon receiving `Report` with such extension (or `ReportShare`
in the case of helper.)

By sending task configuration parameters to clients, we add transparency to the
task that clients participate in. Client can see what privacy parameters has
been configured for a task (for e.g. `min_batch_size`, or any differential
privacy parameters if that's the privacy guarantee used).

By defining this mechanism as an extension, we can guarantee that for any
deployments implementing this extension:

1. Task transparency is enforced since aggregator task must be created using
the same parameters client sent.

2. No need for out-of-band task orchestration between leader and helpers, any
leaders and helpers can work on the same DAP task, therefore making adoption of
DAP easier.

3. A "task" now means the same task ID and same task configuration, including
parameters for choosing VDAF. Therefore, reports from one task will only be
aggregated with one VDAF. For the same reason, if a malicious client changes
the task ID or task configuration, its report will be aggregated in a different
task, with other poison reports from the same malicious attack. The "good"
reports will not be polluted.

Because extension is used in HPKE's AAD, by including all task configurations
in the extension, malicious leader cannot change the task configuration to
mislead helpers to reduce privacy guarantee, for e.g. by reducing
`min_batch_size`.

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

    /* A codepoint defined in I-D.draft-irtf-cfrg-vdaf-03 or reserved for private
    use. */
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
        case fixed-size: uint32 max_batch_size;
    }
} QueryConfig;
~~~

The purpose of `TaskConfig` is to define all parameters that are necessary
for configuring an aggregator. It includes all the fields to be
associated with a task (see task configuration in
{{?DAP=I-D.draft-ietf-ppm-dap-01}}.). Besides, `TaskConfig` also includes fields
that useful for configuring a task in-band:

* An opaque `task_info` that is specific to a task. For e.g. this can be a
string describing the purpose of this task. It can also be the DAP task ID
chosen by task author.

* An opaque `vdaf_config` that contains any VDAF specific parameters for the
chosen `vdaf_type`. The aggregators MUST pass `vdaf_config` to VDAF initialiser,
based on the chosen `vdaf_type`.

The codepoints for standardized (V)DAFs are listed below:

~~~
/* Codepoint for each standardized VDAF. Defined in
 I-D.draft-irtf-cfrg-vdaf-02 */
enum {
    Prio3Aes128Count(0x00000000),
    Prio3Aes128Sum(0x00000001),
    Prio3Aes128Histogram(0x00000002),
    Poplar1Aes128(0x00001000),
    (255)
} VdafType;
~~~

`VdafConfig` is not specified in this document, instead it should be defined by
each VDAF implementation, for example, the simplest VDAF config for Prio3 can
be defined as:

~~~
struct {
    select (vdaf_type) {
        case Prio3Aes128Count: Empty;
        case Prio3Aes128Sum: uint8 bits;
        case Prio3Aes128Histogram: uint32 buckets;
    }
} VdafConfig;
~~~

> OPEN ISSUE: Should DP parameters be defined as a different "dimension" to
> VDAF, given that it's likely various DP mechanisms can be applied to any VDAF.

The definition of Time, Duration, Url, QueryType follow those in
{{?DAP=I-D.draft-ietf-ppm-dap-01}}.

Note that the parameters that are not necessarily tied to a task (for e.g.
collector hpke config), and secrets that should not be known by clients, like
`vdaf_verify_key`, MUST still be exchanged out-of-band among aggregators.

# Client Behavior

> TODO(wangshan) Say how the Client constructs the extension body. Does the
> extension change anything else about the upload flow?

The client should know whether `task-prov` extension will be used and all
parameters required for `TaskConfig` prior to constructing the extension
body, either out-of-band from aggregators, or from information already saved on
client.

To use this extension, the client should first decide what is the task ID, see
{{construct-task-id}}.

## Construct task ID {#construct-task-id}

For `task-prov` extension, a DAP task is not created before distributing task
configuration to clients. Therefore, a DAP task ID may not be available to
clients, aggregators and collector before uploading. Aggregator or collector
MAY still choose a task ID for this task and deliver it to all clients along
with `TaskConfig`. In this case, client MUST use that task ID. This arrangement
SHOULD be agreed by aggregators, collector and clients out-of-band.

Alternatively, task ID can be constructed from `task_info` and any other part
of task configuration, as long as the generated task ID is determinstic and
stay consistent across all parties. For example, the task ID can be a SHA256
hash of the entire serialized `TaskConfig`. In this case, the `task_info`
serves as an unique byte array to distinguish different tasks that share the
same task parameters. Task ID can be constructed on server side and then
distributed to clients, or constructed independently on clients and servers.
When constructed independently, the mechanism used for creating the task ID
must be known to both clients and the collector.

> OPEN ISSUE: Should task ID construction from TaskConfig be enforeced?

## Construct extension body

Client constructs this extension during the upload flow, after hpke config
(see update flow and hpke-config in {{?DAP=I-D.draft-ietf-ppm-dap-01}}.).
Client typically sets `extension_type` to `task-prov` codepoint in
`ReportMetadata`'s extension field, and save the encoded `TaskConfig` in
`extension_data` field.

# Leader Behavior

> TODO(wangshan) Say what the Leader does when it receives a report with this
> extension. What do Leaders do if they *don't* support this extension? Is it
> safe to ignore it? How are the upload, aggregate, and collect flows impacted?

Leader should have saved any information that is not always tied to a
particular task, for e.g. `vdaf_verify_key`. Leader may not know the task ID of
the current task before receiving the first upload request.

## Change to update sub-protocol

Upon receiving a report, leader reads the extension codepoint in
`extension_type`. If leader does not support this extension, it SHOULD abort
the upload protocol and alert the client with error "unrecognizedMessage".

> reason for aborting: if leader ignores it, then there is no way to ensure
> clients that the extension is used and task parameters are respected in
> aggregators

If leader supports `task-prov` extension, it should first check if the task ID
already exists, if so leader continues to the rest of upload flow as usual.
Note if the existing tasks's configuration is different from the one in report
extension, HPKE decryption will fail due to mismatched AAD.

If the task ID has not been seen before, leader should read and decode report's
`extension_data` with the `TaskConfig` schema. If the decoding failed, it MUST
abort the upload protocol and alert the client with error
"unrecognizedMessage".

If the decode succeeds, leader should create a new task using the task ID from
the decoded report, and save task configuration with the newly created task. In
particular, leader should deserialize `vdaf_config` corresponding to `vdaf_type`,
and pass the relevant parameters to the VDAF initializer. At this point, the
task provision step has completed, and leader should continue to the rest of
upload flow.

Leader MAY return error to the client if task creation failed.

> OPEN ISSUE: would returning error reveal the position of the client in the
> batch of reports received? if so is this a security or privacy threat?

## Change to leader aggregate sub-protocol

There is no change to the aggregate sub-protocol on leader side.

## Change to collect sub-protocol

During collect init, leader must perform batch validation (see batch-validation
in {{?DAP=I-D.draft-ietf-ppm-dap-01}}) to the `CollectReq`. This requires leader
to know the parameters associated with the DAP task. However, upon receipt of
`CollectReq`, leader may not know the parameters if the first upload has not
arrived yet. In this case the leader MAY respond with HTTP status code 404
Not Found and an error of type `unrecognizedTask`. The response MAY include a
Retry-After header field to suggest a pulling interval to the collector.

> Alternatively the leader can just response with 303 and continue waiting.

# Helper Behavior

Helper should have received out-of-band from leader any information that is not
always tied to a particular task, for e.g. `vdaf_verify_key`. Similar to
leader, helper may not know the task ID of the current task before receiving
the first `AggregateInitializeReq` message from the leader.

## Change to helper aggregate sub-protocol

Upon receipt of a `AggregateInitializeReq`, helper reads the extension
codepoint in `extension_type`. If helper does not support this extension, it
SHOULD abort the aggregate protocol and alert the leader with error
"unrecognizedMessage".

If helper supports `task-prov` extension, it should first check if the task ID
already exists, if so helper continues to the rest of helper initialization as
usual (see helper initialization in {{?DAP=I-D.draft-ietf-ppm-dap-01}}.)
Note if the existing task's configuration is different from the one in report
share extension, HPKE decryption will fail due to mismatched AAD.

If the task ID has not been seen before, helper should read and decode report
share's `extension_data` with the `TaskConfig` schema. If the decode failed,
it MUST abort the aggregate protocol and alert the leader with error
"unrecognizedMessage".

If the decode succeeds, helper should create a new task using the task ID from
the decoded report share, and save task configuration with the newly created
task. In particular, helper should pass `vdaf_config` to the VDAF initializer,
based on `vdaf_type` in `TaskConfig`. At this point, the task provision step has
completed, and helper should continue to the rest of helper initialization.

# Collector Behavior

> TODO(wangshan) Describe if/how this extension impacts Collector behavior.

If Collector supports `task-prov` extension and receives a HTTP status code
404 Not Found with error type `unrecognizedTask` after sending a `CollectReq`,
it SHOULD retry with the same `CollectReq`, potentially using an interval from
the Retry-After header in the received response.

# Operational Considerations

> NOTE(shan) Do we want to include this section in the beginning?

The in-band task provision mechanism is easy to implement with streaming
framework that has `groupBy` operator. In fact, task as an object doesn't have
to exist in aggregators, it mainly becomes an identifier to group aggregations
together.

This mechanism brings added overhead in `Report` and `ReportShare` since more
duplicated data is passed around. Some optimisation can be done by sending only
one copy of extension in `AggregateInitializeReq`.

# Security Considerations

> NOTE(cjpatton) In this section we would describe any security goals we have
> that go beyond the core DAP spec. We will also discuss if/how the extension
> impacts the security of DAP itself.


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

