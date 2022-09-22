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

The DAP protocol {{!DAP=I-D.draft-ietf-ppm-dap-01}} enables secure aggregation
of a set of reports submitted by Clients. This process is centered around a
"task" that determines, among other things, the cryptographic scheme to use for
the secure computation (a Verifiable Distributed Aggregation Function
{{?VDAF=I-D.draft-irtf-cfrg-vdaf-01}}), how reports are partitioned into
batches, and privacy parameters such as the minimum size of each batch. Before a
task can be executed, it is necessary to first provision the Clients,
Aggregators, and Collector with the task's configuration.

However, The core DAP specification does not define a mechanism for provisioning
tasks. this document describes a mechanism designed to fill this gap. Its key
feature is that task configuration is performed completely in-band. It relies
solely on the upload channel and the metadata carried by reports themselves.

This method presumes the existence of a logical "task author" (written as
"Author" hereafter) who is capable of pushing configurations to Clients. All
parameters required by downstream entities (the Aggregators and Collector) are
encoded in an extension field of the Client's report. There is no need for
out-of-band task orchestration between Leader and Helpers, therefore making
adoption of DAP easier.

The extension is designed with the same security and privacy considerations of
the core DAP protocol. The Author is not regarded as a trusted third party: It
is incumbent on all protocol participants to verify the task configuration
disseminated by the Author and opt-out if the parameters are deemed insufficient
for privacy. In particular, adopters of this extensions should presume the
Author is under the adversary's control. In fact, we expect in a real-world
deployment that the Author may be implemented by one of the Aggregators or
Collector.

Finally, the DAP protocol requires configuring the entities with a variety of
assets that are not task-specific, but are important for establishing
Client-Aggregator, Collector-Aggregator, and Aggregator-Aggregator
relationships. These include:

* The Collector's HPKE {{?RFC9180}} configuration used by the Aggregators to
  encrypt aggregate shares.

* Any assets required for authenticating HTTP requests.

This specification does not specify a mechanism for provisioning these assets;
as in the core DAP protocol, these are presumed to be configured out-of-band.

Note that we consider the VDAF verification key {{!VDAF}}, used by the
Aggregators to aggregate reports, to be a task-specific asset. This document
specifies how to derive this key for a given task from a pre-shared secret,
which in turn is presumed to be configured out-of-band.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the same conventions for error handling as
{{!DAP=I-D.draft-ietf-ppm-dap-01}}. In addition, this document extends the core
specification by adding the following error types:

| Type        | Description                                                                               |
|:------------|:------------------------------------------------------------------------------------------|
| invalidTask | An Aggregator has opted out of the indicated task as described in {{provisioning-a-task}} |

The terms used follow those described in {{!DAP=I-D.draft-ietf-ppm-dap-01}}. The
following new terms are used:

Task configuration:
: The non-secret parameters required to create a task in task provision.

Task author:
: The entity that defines a task's configuration.

# The "task_prov" Extension

A new extension is defined:

~~~
enum {
    task_prov(0xff00),
    (65535)
} ExtensionType;
~~~

When the Client includes this extension with its report, the body of the
extension is a `TaskConfig` defined follows:

~~~
struct {
    /* Info specific for a task. */
    opaque task_info<1..2^8-1>;

    /* A list of URLs relative to which an Aggregator's API endpoints
    can be found. Defined in I-D.draft-ietf-ppm-dap-02. */
    Url aggregator_endpoints<1..2^16-1>;

    /* This determines the query type for batch selection and the
    properties that all batches for this task must have. Defined in
    I-D.draft-ietf-ppm-dap-02. */
    QueryConfig query_config;

    /* Time up to which Clients are allowed to upload to this task. See
    https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/pull/304. Defined
    in I-D.draft-ietf-ppm-dap-02. */
    Time task_expiration;

    /* Determines the VDAF type and its config parameters. */
    VdafConfig vdaf_config;
} TaskConfig;
~~~

The purpose of `TaskConfig` is to define all parameters that are necessary for
configuring an Aggregator. It includes all the fields to be associated with a
task. (See task configuration in {{!DAP=I-D.draft-ietf-ppm-dap-01}}.) In
addition to the Aggregator endpoints, maximum batch lifetime, and task
expiration, the structure includes an opaque `task_info` field that is specific
to a deployment. For example, this can be a string describing the purpose of
this task.

The `query_config` field defines the DAP query configuration used to guide batch
selection. It is defined as follows:

~~~
struct {
    QueryType query_type;      /* Defined in I-D.draft-ietf-ppm-dap-02 */
    Duration time_precision;   /* Defined in I-D.draft-ietf-ppm-dap-02 */
    uint16 max_batch_lifetime; /* Defined in I-D.draft-ietf-ppm-dap-02 */
    uint32 min_batch_size;
    select (QueryConfig.query_type) {
        case time-interval: Empty;
        case fixed-size:    uint32 max_batch_size;
    }
} QueryConfig;
~~~

The `vdaf_config` defines the configuration of the VDAF in use for this task. It
is structured as follows:

~~~
enum {
    prio3-aes128-count(0x00000000),     /* I-D.draft-irtf-cfrg-vdaf-03 */
    prio3-aes128-sum(0x00000001),       /* I-D.draft-irtf-cfrg-vdaf-03 */
    prio3-aes128-histogram(0x00000002), /* I-D.draft-irtf-cfrg-vdaf-03 */
    poplar1-aes128(0x00001000),         /* I-D.draft-irtf-cfrg-vdaf-03 */
    (2^32-1)
} VdafType;

struct {
    DpConfig dp_config;
    VdafType vdaf_type;
    select (VdafConfig.vdaf_type) {
        case prio3-aes128-count: Empty;
        case prio3-aes128-sum: uint8 bits;
        case prio3-aes128-histogram: uint64 buckets<8..2^24-8>;
        case poplar1-aes128: uint16 bits;
    }
} VdafConfig;
~~~

Apart from the VDAF-specific parameters, this structure includes a mechanism for
differential privacy (DP). This field, `dp_config`, is structured as follows:

~~~
enum {
    reserved(0), /* Reserved for testing purposes */
    none(1),
    (255)
} DpMechanism;

struct {
    DpMechanism dp_mechanism;
    select (DpConfig.dp_mechanism) {
        case none: Empty;
    }
} DpConfig;
~~~

> OPEN ISSUE: Should spell out definition of `DcConfig` for various differential
> privacy mechanisms and parameters. See issue
> [#94](https://github.com/cfrg/draft-irtf-cfrg-vdaf/issues/94) for discussion.

The definition of `Time`, `Duration`, `Url`, and `QueryType` follow those in
{{!DAP=I-D.draft-ietf-ppm-dap-02}}.

## Deriving the Task ID {#construct-task-id}

When using the `task_prov` extension, the task ID is computed as follows:

~~~
task_id = SHA-256(task_config)
~~~

where `task_config` is the `TaskConfig` structure disseminated by the Author.

> OPEN ISSUE: Consider using a randomness extractor, such has `HKDF-Extract()`,
> so that we can treat the `task_id` as pseudorandom in cases where
> `task_config` has high min-entropy

> TODO: Add RFC reference for SHA-256.

## Deriving the VDAF Verification Key {#vdaf-verify-key}

> TODO

## Configuring a Task {#provisioning-a-task}

Prior to participating in a task, each protocol participant must determine if
the `TaskConfig` disseminated by the Author can be configured. The participant
is said to "opt in" to the task if the derived task ID (see
{{construct-task-id}}) corresponds to an already configured task or the task ID
is unrecognized and therefore corresponds to a new task.

A protocol participant MAY "opt out" of a task if:

1. The derived task ID corresponds to an already configured task, but the task
   configuration disseminated by the Author does not match the existing
   configuration.

1. The VDAF, DP, or query configuration is deemed insufficient for privacy.

1. A secure connection to one or both of the Aggregator endpoints could not be
   established.

1. The task lifetime is too long.

A protocol participant MUST opt out if the task has expired.

The behavior of each protocol participant is determined by whether or not they
opt in to a task.

# Client Behavior

Upon receiving a `TaskConfig` from the Author, the Client decides whether to
opt in to the task as described in {{provisioning-a-task}}. If the Client opts
out, it MUST not attempt to upload reports for the task.

> OPEN ISSUE: In case of opt-out, would it be useful to specify how to report
> this to the Author?

Once the client opts in to a task, it MAY begin uploading reports for the task.
Each report MUST offer the `task_prov` extension with the `TaskConfig`
disseminated by the Author as the extension payload. In addition, the report's
task ID MUST be computed as described in {{construct-task-id}}.

# Leader Behavior

## Upload Protocol

Upon receiving a `Report` from the Client with the `task_prov` extension, if the
Leader does not support the extension, it MUST ignore the extension payload and
proceed as usual. In particular, if the task ID is not recognized, then it MUST
abort the upload request with "unrecognizedTask".

> NOTE: This behavior assumes unrecognized extensions are to be ignored. See
> [#334](https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/issues/334) for
> discussion.

Otherwise, if the Leader does support the extension, it first attemps to parse
the payload. If parsing fails, it MUST abort with "unrecognizedMessage".

Next, it checks that the task ID included in the report matches the task ID
derived from the extension payload as specified in {{construct-task-id}}. If the
task ID does not match, then the Leader MUST abort with "unrecognizedTask".

The Leader then decides whether to opt in to the task as described in
{{provisioning-a-task}}. If it opts out, it MUST abort the upload request with
"invalidTask".

> OPEN ISSUE: In case of opt-out, would it be useful to specify how to report
> this to the Author?

Finally, once the Leader has opted in to the task, it completes the upload
request as usual.

## Aggregate Protocol

When the Leader opts in to a task, it derives the VDAF verification key for that
task as described in {{vdaf-verify-key}}.

## Collect Protocol

The Collector might issue a collect request for a task provisioned by the
`task_prov` extension prior to opting in to the task. In this case, the Leader
would need to abort the collect request with "unrecognizedTask". When it does
so, it SHOULD also include a "Retry-After" header in its HTTP response
indicating the time after which the Collector should retry its request.

> TODO: Find RFC reference for "Retry-After".

> OPEN ISSUE: This semantics is awkward, as there's no way for the Leader to
> distinguish between Collectors who support the extension and those that don't.
> We should consider adding an extension field to `CollectReq`.

# Helper Behavior

Upon receiving of an `AggregateInitializeReq` from the Leader, If the Helper
does not support the `task_prov` extension, it MUST ignore the extension
payload and process each `ReportShare` as usual. In particular, if the Helper
does not recognize the task ID, it MUST abort the aggregate request with error
"unrecognizedTask". Otherwise, if the Helper supports the extension, it proceeds
as follows.

First, the Helper checks that all report shares carried by the request pertain
to the same task. In particular, it checks that:

1. Either all report shares have the `task_prov` extension or none do. If not
   the Helper MUST abort with "unrecognizedMessage".

1. All report shares with the `task_prov` extension have the same payload. If
   not, the Helper MUST abort with "unrecognizedMessage".

> OPEN ISSUE: This awkward input validation step could be skipped if
> `AggregateInitializeReq` had an extension field that we could stick the task
> configuration in. This would also save significantly in overhead.

Next, the Helper attempts to parse the extension paylaod. If parsing fails, it
MUST abort with "unrecognizedMessage".

Next, the Helper checks that the task ID included in the message matches the
task ID derived from the extension payload ad defined in {{construct-task-id}}.
If not, the Helper MUST abort with "unrecognizedTask".

Next, the Helper decides whether to opt in to the task as described in
{{provisioning-a-task}}. If it opts out, it MUST abort the upload request with
"invalidTask".

> OPEN ISSUE: In case of opt-out, would it be useful to specify how to report
> this to the Author?

Finally, the Helper completes the aggregate initialize request as usual, deriving the VDAF
verification key for the task as described in {{vdaf-verify-key}}.

# Collector Behavior

Upon receiving a `TaskConfig` from the Author, the Collector first decides
whether to opt in to the task as described in {{provisioning-a-task}}. If the
Collector opts out, it MUST not attempt to upload reports for the task.

Otherwise, once opted in, the Collector MAY begin to issue collect requests for
the task. The task ID for each request MUST be derived from the `TaskConfig` as
described in {{provisioning-a-task}}.

If the Leader responds to a collect request with an "unrecognizedTask" error,
but the HTTP response includes a "Retry-After" header, the Collector SHOULD
retry its collect request after waiting for the duration indicated by the
header.

# Security Considerations

This document has the same security and privacy considerations as the core DAP
specification. In particular, for privacy we consider the Author to be under
control of the adversary. It is therefore incumbent on protocol participants to
verify the privacy parameters of a task before opting in.

In addition, the `task_prov` extension is designed to maintain robustness even
when the Author misbehaves, or is merely misconfigured. In particular, if the
Clients and Aggregators have an inconsistent view of the the task configuration,
then aggregation of reports will fail. This is guaranteed by the binding of
report metadata to encrypted input shares provided by HPKE encryption.

> OPEN ISSUE: What if the Collector and Aggregators don't agree on the task
> configuration? Consider adding

A "task" now means the same task ID and same task configuration, if a malicious
client changes the task ID or task configuration, its report will be aggregated
in a different task, with other poison reports from the same malicious attack.
The "good" reports will not be polluted.

> CP: I don't understand the threat here. Is it that the client may lie about
> which task its report is for? The same is true for vanilla DAP, right?

A malicious coalition of Clients might attempt to pollute an Aggregator's
long-term storage by uploading reports for many (thousands or perhaps millions)
of distinct tasks.

> TODO: Suggest mitigations for this.

# IANA Considerations

> NOTE(cjpatton) Eventually we'll have IANA considerations (at the very least
> we'll need to allocate a codepoint) but we can leave this blank for now.

--- back

# Contributors
{:numbered="false"}

> CP: Unless the order is meaningful, consider alphabetizing these names.

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
