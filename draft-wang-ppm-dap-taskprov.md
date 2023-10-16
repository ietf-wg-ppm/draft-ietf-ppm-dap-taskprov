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

  SHS:
     title: "Secure Hash Standard"
     date: 2015-08-04
     seriesinfo: FIPS PUB 180-4

informative:


--- abstract

An extension for the Distributed Aggregation Protocol (DAP) is specified that
allows the task configuration to be provisioned in-band.


--- middle

# Introduction

The DAP protocol {{!DAP=I-D.draft-ietf-ppm-dap-07}} enables secure aggregation
of a set of reports submitted by Clients. This process is centered around a
"task" that determines, among other things, the cryptographic scheme to use for
the secure computation (a Verifiable Distributed Aggregation Function
{{!VDAF=I-D.draft-irtf-cfrg-vdaf-07}}), how reports are partitioned into
batches, and privacy parameters such as the minimum size of each batch. Before a
task can be executed, it is necessary to first provision the Clients,
Aggregators, and Collector with the task's configuration.

The core DAP specification does not define a mechanism for provisioning tasks.
This document describes a mechanism designed to fill this gap. Its key feature
is that task configuration is performed completely in-band. It relies solely on
the upload channel and the metadata carried by reports themselves.

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
for privacy. In particular, adopters of this extension should presume the
Author is under the adversary's control. In fact, we expect in a real-world
deployment that the Author may be implemented by one of the Aggregators or
Collector.

Finally, the DAP protocol requires configuring the entities with a variety of
assets that are not task-specific, but are important for establishing
Client-Aggregator, Collector-Aggregator, and Aggregator-Aggregator
relationships. These include:

* The Collector's HPKE {{!RFC9180}} configuration used by the Aggregators to
  encrypt aggregate shares.

* Any assets required for authenticating HTTP requests.

This document does not specify a mechanism for provisioning these assets; as in
the core DAP protocol; these are presumed to be configured out-of-band.

Note that we consider the VDAF verification key {{!VDAF}}, used by the
Aggregators to aggregate reports, to be a task-specific asset. This document
specifies how to derive this key for a given task from a pre-shared secret,
which in turn is presumed to be configured out-of-band.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the same conventions for error handling as {{!DAP}}. In
addition, this document extends the core specification by adding the following
error types:

| Type        | Description                                                                               |
|:------------|:------------------------------------------------------------------------------------------|
| invalidTask | An Aggregator has opted out of the indicated task as described in {{provisioning-a-task}} |

The terms used follow those described in {{!DAP}}. The following new terms are
used:

Task configuration:
: The non-secret parameters of a task.

Task author:
: The entity that defines a task's configuration.

# The Taskprov Extension {#definition}

The process of provisioning a task begins when the Author disseminates the task
configuration to the Collector and each of the Clients. When a Client issues an
upload request to the Leader (as described in {{Section 4.3 of !DAP}}), it
includes in an HTTP header the task configuration it used to generate the
report. We refer to this process as "task advertisement". Before consuming the
report, the Leader parses the configuration and decides whether to opt-in; if
not, the task's execution halts.

Otherwise, if the Leader does opt-in, it advertises the task to the Helpers
during the aggregate protocol ({{Section 4.4 of !DAP}}). In particular, it
includes the task configuration in an HTTP header of its first aggregate request
for that task. Before proceeding, the Helper must first parse the configuration
and decide whether to opt-in; if not, the task's execution halts.

To advertise a task to its peer, a Taskprov participant includes a header
"dap-taskprov" with a request incident to the task execution. The value is the
`TaskConfig` structure defined below, expanded into its URL-safe, unpadded Base
64 representation as specified in {{Sections 5 and 3.2 of !RFC4648}}.

~~~
struct {
    /* Info specific for a task. */
    opaque task_info<1..2^8-1>;

    /* A list of URLs relative to which an Aggregator's API endpoints
    can be found. Defined in I-D.draft-ietf-ppm-dap-07. */
    Url aggregator_endpoints<1..2^16-1>;

    /* This determines the query type for batch selection and the
    properties that all batches for this task must have. */
    QueryConfig query_config;

    /* Time up to which Clients are allowed to upload to this task.
    Defined in I-D.draft-ietf-ppm-dap-07. */
    Time task_expiration;

    /* Determines the VDAF type and its config parameters. */
    VdafConfig vdaf_config;
} TaskConfig;
~~~

The purpose of `TaskConfig` is to define all parameters that are necessary for
configuring an Aggregator. It includes all the fields to be associated with a
task. In addition to the Aggregator endpoints, maximum batch query count, and
task expiration, the structure includes an opaque `task_info` field that is
specific to a deployment. For example, this can be a string describing the
purpose of this task.

The `query_config` field defines the DAP query configuration used to guide batch
selection. It is defined as follows:

~~~
struct {
    QueryType query_type;         /* I-D.draft-ietf-ppm-dap-07 */
    Duration time_precision;      /* I-D.draft-ietf-ppm-dap-07 */
    uint16 max_batch_query_count; /* I-D.draft-ietf-ppm-dap-07 */
    uint32 min_batch_size;
    select (QueryConfig.query_type) {
        case time_interval: Empty;
        case fixed_size:    uint32 max_batch_size;
    }
} QueryConfig;
~~~

The `vdaf_config` defines the configuration of the VDAF in use for this task. It
is structured as follows (codepoints are as defined in {{!VDAF}}):

~~~
enum {
    prio3_count(0x00000000),
    prio3_sum(0x00000001),
    prio3_sum_vec(0x00000002),
    prio3_histogram(0x00000003),
    poplar1(0x00001000),
    (2^32-1)
} VdafType;

struct {
    DpConfig dp_config;
    VdafType vdaf_type;
    select (VdafConfig.vdaf_type) {
        case prio3_count:
            Empty;
        case prio3_sum:
            uint8;          /* bit length of each summand */
        case prio3_sum_vec:
            uint8;          /* bit length of each summand */
            uint32;         /* number of summands */
            uint32;         /* size of each proof chunk */
        case prio3_histogram:
            uint32;         /* number of buckets */
            uint32;         /* size of each proof chunk */
        case poplar1:
            uint16;         /* bit length of input string */
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

> OPEN ISSUE: Should spell out definition of `DpConfig` for various differential
> privacy mechanisms and parameters. See draft
> [draft](https://github.com/wangshan/draft-wang-ppm-differential-privacy) for discussion.

The definition of `Time`, `Duration`, `Url`, and `QueryType` follow those in
{{!DAP}}.

## Deriving the Task ID {#construct-task-id}

When using the Taskprov extension, the task ID is computed as follows:

~~~
task_id = SHA-256(task_config)
~~~

where `task_config` is the `TaskConfig` structure disseminated by the Author.
Function SHA-256() is as defined in {{SHS}}.

## Deriving the VDAF Verification Key {#vdaf-verify-key}

When a Leader and Helper implement the `taskprov` extension in the context of a
particular DAP deployment, they SHOULD compute the shared VDAF verification key
{{!VDAF}} as described in this section.

The Aggregators are presumed to have securely exchanged a pre-shared secret
out-of-band. The length of this secret MUST be 32 bytes. Let us denote this
secret by `verify_key_init`.

Let `VERIFY_KEY_SIZE` denote the length of the verification key for the VDAF
indicated by the task configuration. (See {{!VDAF, Section 5}}.)

The VDAF verification key used for the task is computed as follows:

~~~
verify_key = HKDF-Expand(
    HKDF-Extract(
        taskprov_salt,  # salt
        verify_key_init, # IKM
    ),
    task_id,             # info
    VERIFY_KEY_SIZE,     # L
)
~~~

where `taskprov_salt` is defined to be the SHA-256 hash of the octet string
"dap-taskprov" and `task_id` is as defined in {{construct-task-id}}. Functions
HKDF-Extract() and HKDF-Expand() are as defined in {{!RFC5869}}. Both functions
are instantiated with SHA-256.

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

## Supporting HPKE Configurations Independent of Tasks {#hpke-config-no-task-id}

In DAP, Clients need to know the HPKE configuration of each Aggregator before
sending reports. (See HPKE Configuration Request in {{!DAP}}.) However, in a DAP
deployment that supports the Taskprov extension, if a Client requests the
Aggregator's HPKE configuration with the task ID computed as described in
{{construct-task-id}}, the task ID may not be configured in the Aggregator yet,
because the Aggregator is still waiting for the task to be advertised by a
Client.

To mitigate this issue, if an Aggregator wants to support the Taskprov
extension, it SHOULD choose which HPKE configuration to advertise to Clients
independent of the task ID. It MAY continue to support per-task HPKE
configurations for other tasks that are configured out-of-band.

In addition, if a Client intends to advertise a task via the Taskprov extension,
it SHOULD NOT specify the `task_id` parameter when requesting the HPKE
configuration from an Aggregator.

# Client Behavior

Upon receiving a `TaskConfig` from the Author, the Client decides whether to
opt in to the task as described in {{provisioning-a-task}}. If the Client opts
out, it MUST not attempt to upload reports for the task.

> OPEN ISSUE: In case of opt-out, would it be useful to specify how to report
> this to the Author?

Once the client opts in to a task, it MAY begin uploading reports for the task.
Each upload request for that task MUST advertise the task configuration. The
extension codepoint `taskprov` MUST be offered in the `extensions` field of
both leader and helper's `PlaintextInputShare`. In addition, each report's task
ID MUST be computed as described in {{construct-task-id}}.

The `taskprov` extension type is defined as follows:

~~~
enum {
    taskprov(0xff00),
    (65535)
} ExtensionType;
~~~

The extension data in report share for `taskprov` is zero length, since its
content is transported in "dap-taskprov" header.


# Leader Behavior

## Upload Protocol

Upon receiving a task advertisement from a Client, if the Leader does not
support the extension, it will ignore the HTTP header. In particular, if the
task ID is not recognized, then it MUST abort the upload request with
"unrecognizedTask".

Otherwise, if the Leader does support the extension, it first attempts to parse
the "dap-taskprov" HTTP header payload. If parsing fails, it MUST abort with
"invalidMessage".

Next, it checks that the task ID indicated by the upload request matches the
task ID derived from the extension payload as specified in
{{construct-task-id}}. If the task ID does not match, then the Leader MUST abort
with "unrecognizedTask".

The Leader then decides whether to opt in to the task as described in
{{provisioning-a-task}}. If it opts out, it MUST abort the upload request with
"invalidTask".

> OPEN ISSUE: In case of opt-out, would it be useful to specify how to report
> this to the Author?

Finally, once the Leader has opted in to the task, it completes the upload
request as usual.

During the upload flow, if Leader's report share does not present a `taskprov`
extension type, Leader MUST abort the upload request wit "invalidMessage".

## Aggregate Protocol

When the Leader opts in to a task, it SHOULD derive the VDAF verification key
for that task as described in {{vdaf-verify-key}}. The Leader MUST advertise
the task to the Helper in every request incident to the task as described in
{{definition}}.

## Collect Protocol

The Collector might issue a collect request for a task provisioned by the
Taskprov extension prior to opting in to the task. In this case, the Leader
would need to abort the collect request with "unrecognizedTask". When it does
so, it is up to the Collector to retry its request.

> OPEN ISSUE: This semantics is awkward, as there's no way for the Leader to
> distinguish between Collectors who support the extension and those that don't.

The Leader MUST advertise the task in every aggregate share request issued to
the Helper as described in {{definition}}.

# Helper Behavior

Upon receiving a task advertisement from the Leader, If the Helper does not
support the Taskprov extension, it will ignore the "dap-taskprov" HTTP header
and process the aggregate request as usual. In particular, if the Helper does
not recognize the task ID, it MUST abort the aggregate request with error
"unrecognizedTask". Otherwise, if the Helper supports the extension, it
proceeds as follows.

First, the Helper attempts to parse payload of the "dap-taskprov" HTTP header.
If this step fails, the Helper MUST abort with "invalidMessage".

Next, the Helper checks that the task ID indicated in the upload request matches
the task ID derived from the `TaskConfig` as defined in {{construct-task-id}}.
If not, the Helper MUST abort with "unrecognizedTask".

Next, the Helper decides whether to opt in to the task as described in
{{provisioning-a-task}}. If it opts out, it MUST abort the aggregate request
with "invalidTask".

> OPEN ISSUE: In case of opt-out, would it be useful to specify how to report
> this to the Author?

Finally, the Helper completes the aggregate initialize request as usual,
deriving the VDAF verification key for the task as described in
{{vdaf-verify-key}}.

During Helper aggregate initialization, if any Helper's report share does not
include the `taskprov` extension with an empty payload, then the Helper MUST
abort the aggregate request with "invalidMessage".

# Collector Behavior

Upon receiving a `TaskConfig` from the Author, the Collector first decides
whether to opt in to the task as described in {{provisioning-a-task}}. If the
Collector opts out, it MUST not attempt to upload reports for the task.

Otherwise, once opted in, the Collector MAY begin to issue collect requests for
the task. The task ID for each request MUST be derived from the `TaskConfig` as
described in {{provisioning-a-task}}. The Collector MUST advertise the task as
described in {{definition}}.

If the Leader responds to a collect request with an "unrecognizedTask" error,
the Collector MAY retry its collect request after waiting for a duration.
header.

# Security Considerations

This document has the same security and privacy considerations as the core DAP
specification. In particular, for privacy we consider the Author to be under
control of the adversary. It is therefore incumbent on protocol participants to
verify the privacy parameters of a task before opting in.

In addition, the Taskprov extension is designed to maintain robustness even when
the Author misbehaves, or is merely misconfigured. In particular, if the Clients
and Aggregators have an inconsistent view of the the task configuration, then
aggregation of reports will fail. This is guaranteed by the binding of the task
ID (derived from the task configuration) to report shares provided by HPKE
encryption. Furthermore, the presence of `taskprov` extension type in the report
share means Aggregators that do not recognize Taskprov extension must abort with
`invalidMessage`, as described in ({{Section 4.4.3 of !DAP}}). This prevents a
malicious Author from provisioning a modified task to each party with other
means, which can lead to compromised privacy guarantee in aggregate result.

> OPEN ISSUE: What if the Collector and Aggregators don't agree on the task
> configuration? Decryption should fail.

A malicious coalition of Clients might attempt to pollute an Aggregator's
long-term storage by uploading reports for many (thousands or perhaps millions)
of distinct tasks. While this does not directly impact tasks used by honest
Clients, it does present a Denial-of-Service risk for the Aggregators
themselves.

> TODO: Suggest mitigations for this. Perhaps the Aggregators need to keep track
> of how many tasks in total they are opted in to?

# Operational Considerations

The taskprov extension is designed so that the Aggregators do not need to store
individual task configurations long-term. Because the task configuration is
advertised in each request in the upload, aggregation, and colletion protocols,
the process of opting-in and deriving the task ID and VDAF verify key can be
re-run on the fly for each request. This is useful if a large number of
concurrent tasks are expected.

Once an Aggregator has opted-in to a task, the expectation is that the task is
supported until it expires. In particular, Aggregators that operate in this
manner MUST NOT opt out once they have opted in.

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

Suman Ganta
Apple Inc.
sganta2@apple.com

Gianni Parsa
Apple Inc.
gianni_parsa@apple.com

Michael Scaria
Apple Inc.
mscaria@apple.com

Kunal Talwar
Apple Inc.
ktalwar@apple.com

Christopher A. Wood
Cloudflare
caw@heapingbits.net
