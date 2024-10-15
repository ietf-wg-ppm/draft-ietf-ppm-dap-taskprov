---
title: "Task Binding and In-Band Provisioning for DAP"
abbrev: DAP-Taskprov
category: info

docname: draft-ietf-ppm-dap-taskprov-latest
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
  github: "ietf-wg-ppm/draft-ietf-ppm-dap-taskprov"
  latest: "https://ietf-wg-ppm.github.io/draft-ietf-ppm-dap-taskprov/draft-ietf-ppm-dap-taskprov.html"

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
cryptographically binds the parameters of a task to the task's execution. In
particular, when a client includes this extension with its report, the servers
will only aggregate the report if all parties agree on the task parameters.
This document also specifies an optional mechanism for in-band task
provisioning that builds on the report extension.


--- middle

# Introduction

The DAP protocol {{!DAP=I-D.draft-ietf-ppm-dap-12}} enables secure aggregation
of a set of reports submitted by Clients. This process is centered around a
"task" that determines, among other things, the cryptographic scheme to use for
the secure computation (a Verifiable Distributed Aggregation Function
{{!VDAF=I-D.draft-irtf-cfrg-vdaf-12}}), how reports are partitioned into
batches, and privacy parameters such as the minimum size of each batch. See
{{Section 4.2 of !DAP}} for a complete listing.

In order to execute a task securely, it is required that all parties agree on
all parameters associated with the task. However, the core DAP specification
does not specify a mechanism for accomplishing this. In particular, it is
possible that the parties successfully aggregate and collect a batch, but some
party does not know the parameters that were enforced.

A desirable property for DAP to guarantee is that successful execution implies
agreement on the task parameters. On the other hand, disagreement between a
Client and the Aggregators should prevent reports uploaded by that Client from
being processed.

{{definition}} specifies a report extension ({{Section 4.4.3 of !DAP}}) that
endows DAP with this property. First, it specifies an encoding of all task
parameters that are relevant to all parties. This excludes cryptographic
assets, such as the secret VDAF verification key ({{Section 5 of !VDAF}}) or
the public HPKE configurations {{!RFC9180}} of the aggregators or collector.
Second, the task ID is computed by hashing the encoded parameters. If a report
includes the extension, then each aggregator checks if the task ID was computed
properly: if not, it rejects the report. This cryptographic binding of the task
to its parameters ensures that the report is only processed if the client and
aggregator agree on the task parameters.

One reason this task-binding property is desirable is that it makes the process
by which parties are provisioned with task parameters more robust. This is
because misconfiguration of a party would manifest in a server's telemetry as
report rejection. This is preferable to failing silently, as misconfiguration
could result in privacy loss.

{{taskprov}} specifies one possible mechanism for provisioning DAP tasks that
is built on top of the extension in {{definition}}. Its chief design goal is to
make task configuration completely in-band, via HTTP request headers. Note that
this mechanism is an optional feature of this specification; it is not required
to implement the protocol extension in {{definition}}.

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
: The entity that defines a task's configuration in the provisioning mechanism of {{taskprov}}.

# The Taskbind Extension {#definition}

To use the Taskbind extension, the Client includes the following extension in
the report extensions for each Aggregator as described in {{Section 4.4.3 of
!DAP}}:

(RFC EDITOR: Change this to the IANA-assigned codepoint.)

~~~
enum {
    taskbind(0xff00),
    (65535)
} ExtensionType;
~~~

The payload of the extension MUST be empty. If the payload is non-empty, then
the Aggregator MUST reject the report.

When the client uses the Taskbind extension, it computes the task ID ({{Section
4.2 of !DAP}}) as follows:

~~~
task_id = SHA-256(SHA-256("dap-taskprov task id") || task_config)
~~~

where `task_config` is a `TaskConfig` structure defined in {{task-encoding}}.
Function SHA-256() is as defined in {{SHS}}.

The task ID is bound to each report share (via HPKE authenticated and
associated data, see {{Section 4.4.2 of !DAP}}). Binding the parameters to the
ID this way ensures, in turn, that the report is only aggregated if the Client
and Aggregator agree on the parameters. This is accomplished by the Aggregator
behavior below.

During aggregation ({{Section 4.5 of !DAP}}), each Aggregator processes a
report with the Taskbind extension as follows.

First, it looks up the ID and parameters associated with the task. Note the
task has already been configured; otherwise the Aggregator would have already
aborted the request due to not recognizing the task.

Next, the Aggregator encodes the parameters as a `TaskConfig` defined in
{{task-encoding}} and computes the task ID as above. If the derived task ID
does not match the task ID of the request, then it MUST reject the report with
error "invalid_message".

During the upload flow ({{Section 4.4 of !DAP}}), the Leader SHOULD abort the
request with "unrecognizedTask" if the derived task ID does not match the task
ID of the request.

## Task Encoding

The task configuration is encoded as follows:

~~~
struct {
    /* Info specific for a task. */
    opaque task_info<1..2^8-1>;

    /* Leader API endpoint. */
    Url leader_aggregator_endpoint;

    /* Helper API endpointl. */
    Url helper_aggregator_endpoint;

    /* The batch mode and its parameters. */
    opaque batch_config<1..2^16-1>;

    /* Time up to which Clients are allowed to upload to this
    task. */
    Time task_expiration;

    /* Determines the VDAF type and its config parameters. */
    opaque vdaf_config<1..2^16-1>;
} TaskConfig;
~~~

The purpose of `TaskConfig` is to define all parameters that are necessary for
configuring each party. It includes all the fields to be associated with a
task. It also includes an opaque `task_info` field that is specific to a
deployment. For example, this can be a string describing the purpose of this
task. It does not include cryptographic assets shared by only a subset of the
parties, including the secret VDAF verification key {{!VDAF}} or public HPKE
configurations {{!RFC9180}}.

The `batch_config` field defines the DAP batch mode. Its contents are as follows:

~~~
struct {
    Duration time_precision;
    uint32 min_batch_size;
    BatchMode batch_mode;
    select (BatchMode.batch_mode) {
        case time_interval:   Empty;
        case leader_selected: Empty;
    };
} BatchConfig;
~~~

The length prefix of the `query_config` ensures that the `QueryConfig` structure
can be decoded even if an unrecognized variant is encountered (i.e., an
unimplemented query type).

The `vdaf_config` defines the configuration of the VDAF in use for this task.
Its content is as follows (codepoints are as defined in
{{Section 10 of !VDAF}}):

~~~
enum {
    reserved(0x00000000),
    prio3_count(0x00000001),
    prio3_sum(0x00000002),
    prio3_sum_vec(0x00000003),
    prio3_histogram(0x00000004),
    prio3_multihot_count_vec(0x00000005),
    poplar1(0x00000006),
    (2^32-1)
} VdafType;

struct {
    opaque dp_config<1..2^16-1>;
    VdafType vdaf_type;
    select (VdafConfig.vdaf_type) {
        case prio3_count:
            Empty;
        case prio3_sum:
            uint8;  /* bit length of the summand */
        case prio3_sum_vec:
            uint32; /* length of the vector */
            uint8;  /* bit length of each summand */
            uint32; /* size of each proof chunk */
        case prio3_histogram:
            uint32; /* number of buckets */
            uint32; /* size of each proof chunk */
        case poplar1:
            uint16; /* bit length of input string */
    };
} VdafConfig;
~~~

The length prefix of the `vdaf_config` ensures that the `VdafConfig` structure
can be decoded even if an unrecognized variant is encountered (i.e., an
unimplemented VDAF).

Apart from the VDAF-specific parameters, this structure includes a mechanism for
differential privacy (DP). The opaque `dp_config` contains the following structure:

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
    };
} DpConfig;
~~~

The length prefix of the `dp_config` ensures that the `DpConfig` structure can
be decoded even if an unrecognized variant is encountered (i.e., an
unimplemented DP mechanism).

The definition of `Time`, `Duration`, `Url`, and `BatchMode` follow those in
{{!DAP}}.

# In-band Task Provisioning with the Taskbind Extension {#taskprov}

Before a task can be executed, it is necessary to first provision the Clients,
Aggregators, and Collector with the task's configuration. The core DAP
specification does not define a mechanism for provisioning tasks. This section
describes a mechanism whose key feature is that task configuration is
performed completely in-band, via HTTP request headers.

This method presumes the existence of a logical "task author" (written as
"Author" hereafter) who is capable of pushing configurations to Clients. All
parameters required by downstream entities (the Aggregators) are carried by HTTP
headers piggy-backed on the protocol flow.

This mechanism is designed with the same security and privacy considerations of
the core DAP protocol. The Author is not regarded as a trusted third party: it
is incumbent on all protocol participants to verify the task configuration
disseminated by the Author and opt-out if the parameters are deemed insufficient
for privacy. In particular, adopters of this mechanism should presume the
Author is under the adversary's control. In fact, we expect in a real-world
deployment that the Author may be co-located with the Collector.

The DAP protocol also requires configuring the entities with a variety of assets
that are not task-specific, but are important for establishing
Client-Aggregator, Collector-Aggregator, and Aggregator-Aggregator
relationships. These include:

* The Collector's HPKE {{!RFC9180}} configuration used by the Aggregators to
  encrypt aggregate shares.

* Any assets required for authenticating HTTP requests.

This section does not specify a mechanism for provisioning these assets; as in
the core DAP protocol; these are presumed to be configured out-of-band.

Note that we consider the VDAF verification key {{!VDAF}}, used by the
Aggregators to aggregate reports, to be a task-specific asset. This document
specifies how to derive this key for a given task from a pre-shared secret,
which in turn is presumed to be configured out-of-band.

## Overview

The process of provisioning a task begins when the Author disseminates the task
configuration to the Collector and each of the Clients. When a Client issues an
upload request to the Leader (as described in {{Section 4.3 of !DAP}}), it
includes in an HTTP header the task configuration it used to generate the
report. We refer to this process as "task advertisement". Before consuming the
report, the Leader parses the configuration and decides whether to opt-in; if
not, the task's execution halts.

Otherwise, if the Leader does opt-in, it advertises the task to the Helper
during the aggregation protocol ({{Section 4.4 of !DAP}}). In particular, it
includes the task configuration in an HTTP header of each aggregation job
request for that task. Before proceeding, the Helper must first parse the
configuration and decide whether to opt-in; if not, the task's execution halts.

## Task Advertisement

To advertise a task to its peer, a protocol participant includes a header
"dap-taskprov" with a request incident to the task execution. The value is the
`TaskConfig` structure defined {{task-encoding}}, expanded into its URL-safe,
unpadded Base 64 representation as specified in {{Sections 5 and 3.2 of
!RFC4648}}.

## Deriving the VDAF Verification Key {#vdaf-verify-key}

When a Leader and Helper implement this mechanism, they SHOULD compute the
shared VDAF verification key {{!VDAF}} as described in this section.

The Aggregators are presumed to have securely exchanged a pre-shared secret
out-of-band. The length of this secret MUST be 32 bytes. Let us denote this
secret by `verify_key_init`.

Let `VERIFY_KEY_SIZE` denote the length of the verification key for the VDAF
indicated by the task configuration. (See {{!VDAF, Section 5}}.)

The VDAF verification key used for the task is computed as follows:

~~~
verify_key = HKDF-Expand(
    HKDF-Extract(
        SHA-256("dap-taskprov"), # salt
        verify_key_init,         # IKM
    ),
    task_id,                     # info
    VERIFY_KEY_SIZE,             # L
)
~~~

where `task_id` is as defined in {{definition}}. Functions HKDF-Extract() and
HKDF-Expand() are as defined in {{!RFC5869}}. Both functions are instantiated
with SHA-256.

## Opting into a Task {#provisioning-a-task}

Prior to participating in a task, each protocol participant must determine if
the `TaskConfig` disseminated by the Author can be configured. The participant
is said to "opt in" to the task if the derived task ID (see
{{definition}}) corresponds to an already configured task or the task ID
is unrecognized and therefore corresponds to a new task.

A protocol participant MAY "opt out" of a task if:

1. The derived task ID corresponds to an already configured task, but the task
   configuration disseminated by the Author does not match the existing
   configuration.

1. The VDAF config, DP mechanism, or other parameters are deemed insufficient
   for privacy.

1. A secure connection to one or both of the Aggregator endpoints could not be
   established.

1. The task lifetime is too long.

A protocol participant MUST opt out if the task has expired or if it does not
support an indicated task parameter (e.g., VDAF, DP mechanism, or DAP batch
mode).

The behavior of each protocol participant is determined by whether or not they
opt in to a task.

## Supporting HPKE Configurations Independent of Tasks {#hpke-config-no-task-id}

In DAP, Clients need to know the HPKE configuration of each Aggregator before
sending reports. (See HPKE Configuration Request in {{!DAP}}.) However, in a
DAP deployment that supports the task provisioning mechanism described in this
section, if a Client requests the Aggregator's HPKE configuration with the task
ID computed as described in {{definition}}, the task ID may not be configured
in the Aggregator yet, because the Aggregator is still waiting for the task to
be advertised by a Client.

To mitigate this issue, each Aggregator SHOULD choose which HPKE configuration
to advertise to Clients independent of the task ID. It MAY continue to support
per-task HPKE configurations for other tasks that are configured out-of-band.

In addition, if a Client intends to advertise a task via the Taskbind extension,
it SHOULD NOT specify the `task_id` parameter when requesting the HPKE
configuration from an Aggregator.

## Client Behavior

Upon receiving a `TaskConfig` from the Author, the Client decides whether to
opt into the task as described in {{provisioning-a-task}}. If the Client opts
out, it MUST not attempt to upload reports for the task.

Once the client opts into a task, it may begin uploading reports for the task
to the Leader. The extension codepoint `taskbind` MUST be offered in the
`extensions` field of both Leader and Helper's `PlaintextInputShare`. In
addition, each report's task ID MUST be computed as described in {{definition}}.

The Client SHOULD advertise the task configuration by specifying the encoded
`TaskConfig` described in {{definition}} in the "dap-taskprov" HTTP header, but
MAY choose to omit this header in order to save network bandwidth. However, the
Leader may respond with "unrecognizedTask" if it has not been configured with
this task. In this case, the Client MUST retry the upload request with the
"dap-taskprov" HTTP header.

## Leader Behavior

### Upload Protocol

Upon receiving a Client report, if the Leader does not support the {{taskprov}}
mechanism, it will ignore the "dap-taskprov" HTTP header. In particular, if the
task ID is not recognized, then it MUST abort the upload request with
"unrecognizedTask".

Otherwise, if the Leader does support this mechanism, it first checks if the
"dap-taskprov" HTTP header is specified. If not, that means the Client has
skipped task advertisement. If the Leader recognizes the task ID, it will
include the client report in the aggregation of that task ID. Otherwise, it
MUST abort with "unrecognizedTask". The Client will then retry with the task
advertisement.

If the Client advertises the task, the Leader checks that the task ID indicated
by the upload request matches the task ID derived from the "dap-taskprov" HTTP
header as specified in {{definition}}. If the task ID does not match, then the
Leader MUST abort with "unrecognizedTask".

The Leader then decides whether to opt in to the task as described in
{{provisioning-a-task}}. If it opts out, it MUST abort the upload request with
"invalidTask".

Finally, once the Leader has opted in to the task, it completes the upload
request as usual.

During the upload flow, if the Leader's report share does not present a
`taskbind` extension type, Leader MUST abort the upload request with
"invalidMessage".

### Aggregate Protocol

When the Leader opts in to a task, it SHOULD derive the VDAF verification key
for that task as described in {{vdaf-verify-key}}. The Leader MUST advertise
the task to the Helper in every request incident to the task as described in
{{definition}}.

### Collect Protocol

The Collector might issue a collect request for a task provisioned by this
mechanism prior to opting into the task. In this case, the Leader would need to
abort the collect request with "unrecognizedTask". When it does so, it is up to
the Collector to retry its request.

> OPEN ISSUE: This semantics is awkward, as there's no way for the Leader to
> distinguish between Collectors who support this mechanism and those that don't.

The Leader MUST advertise the task in every aggregate share request issued to
the Helper as described in {{task-advertisement}}.

## Helper Behavior

Upon receiving a task advertisement from the Leader, If the Helper does not
support this mechanism, it will ignore the "dap-taskprov" HTTP header and
process the aggregate request as usual. In particular, if the Helper does not
recognize the task ID, it MUST abort the aggregate request with error
"unrecognizedTask". Otherwise, if the Helper supports this mechanism, it
proceeds as follows.

First, the Helper attempts to parse payload of the "dap-taskprov" HTTP header.
If this step fails, the Helper MUST abort with "invalidMessage".

Next, the Helper checks that the task ID indicated in the aggregation request
matches the task ID derived from the `TaskConfig` as defined in {{definition}}.
If not, the Helper MUST abort with "unrecognizedTask".

Next, the Helper decides whether to opt in to the task as described in
{{provisioning-a-task}}. If it opts out, it MUST abort the aggregation job
request with "invalidTask".

Finally, the Helper completes the request as usual, deriving the VDAF
verification key for the task as described in {{vdaf-verify-key}}. For any
report share that does not include the `taskbind` extension with an empty
payload, the Helper MUST mark the report as invalid with error
"invalid_message" and reject it.

## Collector Behavior

Upon receiving a `TaskConfig` from the Author, the Collector first decides
whether to opt into the task as described in {{provisioning-a-task}}. If the
Collector opts out, it MUST NOT attempt to issue collect requests for the task.

Otherwise, once opted in, the Collector MAY begin to issue collect requests for
the task. The task ID for each request MUST be derived from the `TaskConfig` as
described in {{provisioning-a-task}}. The Collector MUST advertise the task as
described in {{definition}}.

If the Leader responds to a collect request with an "unrecognizedTask" error,
the Collector MAY retry its collect request after waiting an appropriate amount
of time.

# Security Considerations

The Taskbind extension has the same security and privacy considerations as the
core DAP protocol. In addition, successful execution of a DAP task implies
agreement on the task configuration. This is provided by binding the
parameters to the task ID, which in turn is bound to each report uploaded for a
task. Furthermore, inclusion of the Taskbind extension in the report share
means Aggregators that do not implement this extension will reject the report
as required by ({{Section 4.5.1.4 of !DAP}}).

The task provisioning mechanism in {{taskprov}} extends the threat model of DAP
by including a new logical role, called the Author. The Author is responsible
for configuring Clients prior to task execution. For privacy we consider the
Author to be under control of the adversary. It is therefore incumbent on
protocol participants to verify the privacy parameters of a task before opting
in.

Another risk is that the Author could configure a unique task to fingerprint a
Client. Although Client anonymization is not guaranteed by DAP, some systems
built on top of DAP may hope to achieve this property by using a proxy server
with Oblivious HTTP {{!RFC9458}} to forward Client reports to the Leader. If the
Author colludes with the Leader, the attacker can learn some metadata
information about the Client, e.g., the Client IP, user agent string, which may
deanonymize the Client. However, even if the Author succeeds in doing so, the
Author should learn nothing other than the fact that the Client has uploaded a
report, assuming the Client has verified the privacy parameters of the task
before opting into it. For example, if a task is uniquely configured for the
Client, the Client can enforce the minimum batch size is strictly more than 1.

Another risk for the Aggregators is that a malicious coalition of Clients might
attempt to pollute an Aggregator's long-term storage by uploading reports for
many (thousands or perhaps millions) of distinct tasks. While this does not
directly impact tasks used by honest Clients, it does present a
Denial-of-Service risk for the Aggregators themselves. This can be mitigated by
limiting the rate at which new tasks are configured. In addition, deployments
SHOULD arrange for the Author to digitally sign the task configuration so that
Clients cannot forge task creation.

# Operational Considerations

The Taskbind extension does not introduce any new operational considerations
for DAP.

The task provisioning mechanism in {{taskprov}} is designed so that the
Aggregators do not need to store individual task configurations long-term.
Because the task configuration is advertised in each request in the upload,
aggregation, and collection protocols, the process of opting-in and deriving the
task ID and VDAF verify key can be re-run on the fly for each request. This is
useful if a large number of concurrent tasks are expected. Once an Aggregator
has opted-in to a task, the expectation is that the task is supported until it
expires. In particular, Aggregators that operate in this manner MUST NOT opt
out once they have opted in.

# IANA Considerations

> NOTE(cjpatton) Eventually we'll have IANA considerations (at the very least
> we'll need to allocate a codepoint) but we can leave this blank for now.

--- back

# Contributors
{:numbered="false"}

Junye Chen
Apple Inc.
junyec@apple.com

David Cook
ISRG
divergentdave@gmail.com

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
