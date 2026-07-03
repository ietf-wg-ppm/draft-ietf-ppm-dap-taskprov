---
title: "In-Band Task Provisioning for DAP"
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

This document defines a mechanism for provisioning tasks for the Distributed
Aggregation Protocol (DAP). The task configuration is provisioned in-band via an
HTTP header. This document also specifies a task extension that signals to
parties that this mechanism was used to configure the task.


--- middle

# Introduction

(RFC EDITOR: Remove this paragraph.) This draft is maintained in
https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap-taskprov.

The Distributed Aggregation Protocol {{!DAP=I-D.draft-ietf-ppm-dap-18}} enables
secure aggregation of a set of reports submitted by Clients. This process is
centered around a "task" that determines, among other things, the cryptographic
scheme to use for the secure computation (a Verifiable Distributed Aggregation
Function {{!VDAF=I-D.draft-irtf-cfrg-vdaf-19}}), how reports are partitioned
into batches, and privacy parameters such as the minimum size of each batch.

{{taskprov}} specifies one possible mechanism for provisioning DAP tasks that is
built on top of the task configuration definition in {{Section 4.2 of !DAP}}.
Its chief design goal is to make task configuration completely in-band, via HTTP
request headers. It also defines a task extension that signals to parties that
this mechanism was used to configure the task.

## Change Log

(RFC EDITOR: Remove this section.)

(\*) Indicates a change that breaks wire compatibility with the previous draft.

05:

- Task binding is moved to {{!DAP}}
  (https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/pull/774).  (\*)

- Move report extension to a task extension to make reports smaller.  (\*)

04:

- Redefine `time_precision` as its own `TimePrecision` type, to maintain
  compatibility with DAP-16 {{!DAP}}.

03:

- Handle repeated extensions in the `TaskprovExtension` field of the
  `TaskConfig` as an error.

- Go back to calling the extension "Taskprov". The name "Taskbind" didn't
  stick.

- Add task enumeration attacks to security considerations.

- Add registration of the "DAP-Taskprov" to IANA considerations.

- Bump draft-ietf-ppm-dap-13 to 16 {{!DAP}}.  (\*)

- Bump draft-irtf-cfrg-vdaf-13 to 15 {{!VDAF}}.

02:

- Don't specify a lower limit for vector bounds.

- Update normative references.

- Recommend including the report extension in the public extensions list.

01:

- Add an extension point to the `TaskConfig` structure and define rules for
  processing extensions. (\*)

- Remove DP mechanisms. (\*)

- Add guidelines for extending this document to account for new VDAFs or DAP
  batch modes. Improve the extension points for these in `TaskConfig` in order
  to make this easier. (\*)

- Add a salt to the task ID computation. (\*)

- Harmonize task lifetime parameters with {{!DAP}} by adding a task start time
  and replacing the task end time with a task duration. (\*)

- Harmonize batch mode parameters with {{!DAP}} by removing the deprecated
  `max_batch_query_count` and `max_batch_size` parameters. (\*)

- Task provisioning: Remove guidance for per-task HPKE configurations, as this
  feature was deprecated by DAP.

- Bump draft-ietf-ppm-dap-12 to 13 {{!DAP}}. (\*)

- Bump draft-irtf-cfrg-vdaf-12 to 13 {{!VDAF}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the same conventions for error handling as {{!DAP}}. In
addition, this document extends the core specification by adding the following
error types:

| Type        | Description                                                                               |
|:------------|:------------------------------------------------------------------------------------------|
| invalidTask | An Aggregator has opted out of the indicated task as described in {{provisioning-a-task}} |
{: #urn-space-errors = "DAP errors for the sub-namespace of the DAP URN, e.g., urn:ietf:params:ppm:dap:error:invalidTask."}

The terms used follow those described in {{!DAP}}. The following new terms are
used:

Task author:
: The entity that defines a task's configuration in the provisioning mechanism of {{taskprov}}.

# The Taskprov Task Extension {#definition}

When Taskprov is in use, protocol participants include a `Taskprov` extension
(see {{task-extension}}) in the task's `TaskConfiguration` structure as
described in {{Section 4.2 of !DAP}}.

The payload of the extension MUST be empty. If the payload is non-empty, then
the protocol participant MUST refuse to participate in the task.

When the client uses the Taskprov extension, it computes the task ID ({{Section
4.2 of !DAP}}) as follows:

~~~
task_id = SHA-256(SHA-256("dap-taskprov task id") || task_config)
~~~

where `task_config` is a `TaskConfiguration` structure. Function SHA-256() is as
defined in {{SHS}}.

The task configuration is bound to each report share (via HPKE authenticated and
associated data, see {{Section 4.4.2.1 of !DAP}}). Deterministically deriving the
task ID from the encoded `TaskConfiguration` ensures that Clients, Aggregators
and the Collector can only agree on the task ID if they also agree on the
parameters, including whether Taskprov is in use. This is accomplished by the
following Aggregator behavior.

During aggregation ({{Section 4.5 of !DAP}}) in a task where Taskprov is in use,
each Aggregator processes reports as follows.

First, it looks up the ID and parameters associated with the task. Note the
task has already been configured; otherwise the Aggregator would have already
aborted the request due to not recognizing the task.

Next, the Aggregator encodes the parameters as a `TaskConfiguration` defined in
{{Section 4.2 of !DAP}} and computes the task ID as above. If the derived task
ID does not match the task ID of the request, then it MUST reject the report
with error "invalid_message".

During the upload interaction ({{Section 4.4 of !DAP}}), the Leader SHOULD
abort the request with "unrecognizedTask" if the derived task ID does not match
the task ID of the request.

# In-band Task Provisioning with the Taskprov Extension {#taskprov}

Before a task can be executed, it is necessary to first provision the Clients,
Aggregators, and Collector with the task's configuration. The core DAP
specification does not define a mechanism for provisioning tasks. This section
describes a mechanism whose key feature is that task configuration is
performed completely in-band in an HTTP header field {{!RFC9651}}.

This method presumes the existence of a logical "task author" (written as
"Author" hereafter) who is capable of pushing configurations to Clients. All
parameters required by downstream entities (the Aggregators) are carried by a
header piggy-backed on the protocol flow.

This mechanism is designed with the same security and privacy considerations of
the core DAP protocol. The Author is not regarded as a trusted third party: it
is incumbent on all protocol participants to verify the task configuration
disseminated by the Author and opt-out if the parameters are deemed insufficient
for privacy. In particular, adopters of this mechanism should presume the
Author is under the adversary's control. In fact, we expect in a real-world
deployment that the Author may be co-located with the Collector.

The DAP protocol also requires configuring the entities with a variety of assets
that are not task-specific, but are important for establishing
Client-Aggregator, Collector-Aggregator, and Aggregator-Aggregator
relationships. These include:

* The Collector's HPKE {{!RFC9180}} configuration used by the Aggregators to
  encrypt aggregate shares.

* Any assets required for authenticating HTTP requests.

This section does not specify a mechanism for provisioning these assets. As in
the core DAP protocol, these are presumed to be configured out-of-band.

Note that we consider the VDAF verification key {{!VDAF}}, used by the
Aggregators to aggregate reports, to be a task-specific asset. This document
specifies how to derive this key for a given task from a pre-shared secret,
which in turn is presumed to be configured out-of-band.

## Overview

The process of provisioning a task begins when the Author disseminates the task
configuration to the Collector and each of the Clients. When a Client issues an
upload request to the Leader (as described in {{Section 4.5 of !DAP}}), it
includes in an HTTP header field {{!RFC9651}} the task configuration it used to
generate the report. We refer to this process as "task advertisement". Before
consuming the report, the Leader parses the configuration and decides whether
to opt-in; if not, the task's execution halts.

Otherwise, if the Leader does opt-in, it advertises the task to the Helper
during the aggregation interaction ({{Section 4.5 of !DAP}}). In particular, it
includes the task configuration in an HTTP header of each aggregation job
request for that task. Before proceeding, the Helper must first parse the
configuration and decide whether to opt-in; if not, the task's execution halts.

## DAP-Taskprov Structured Header {#task-advertisement}

The DAP-Taskprov HTTP header is used to advertise a task.

DAP-Taskprov is an Item Structured Header Field {{!RFC9651}}. Its value MUST be
a Byte Sequence ({{Section 3.3.5 of !RFC9651}}). Values of other types MUST be
ignored.

Its value conveys the task configuration with which the recipient is meant to
process the DAP request. It MUST be a valid `TaskConfiguration` as defined in
{{Section 4.2 of !DAP}}. Otherwise, the value MUST be ignored.

This document does not define any parameters for the header. Any parameters
that are present MUST be ignored.

For example:

~~~
    DAP-Taskprov: :AWYAFGh0dHBzOi8vZXhhbXBsZS5jb20vABxodHRwczovL2Fub3RoZXIuZXhhbXBsZS5jb20vAAAAAAAAA+gAAAPoAgAAAAAAAAAAJxAAAAAAAAACXQAAAAIABAAAAP8ACAAAAAQwMTIz:
~~~

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
with `SHA-256()` as defined in {{SHS}}.

## Opting into a Task {#provisioning-a-task}

Prior to participating in a task, each protocol participant must determine if
the `TaskConfiguration` disseminated by the Author can be configured. The
participant is said to "opt in" to the task if the derived task ID (see
{{definition}}) corresponds to an already configured task or the task ID
is unrecognized and therefore corresponds to a new task.

A protocol participant MAY "opt out" of a task if:

1. The derived task ID corresponds to an already configured task, but the task
   configuration disseminated by the Author does not match the existing
   configuration.

1. The VDAF config or other parameters are deemed insufficient for privacy.

1. A secure connection to one or both of the Aggregator endpoints could not be
   established.

1. The task lifetime is too long (if the `task_interval` task extension is in
   use; see {{Section 4.2.3 of !DAP}}).

A protocol participant MUST opt out if:

1. The task has ended (if the `task_interval` task extension is in use; see
   {{Section 4.2.3 of !DAP}}).

1. The DAP batch mode or VDAF is not implemented.

The behavior of each protocol participant is determined by whether or not they
opt in to a task.

## Client Behavior

Upon receiving a `TaskConfiguration` from the Author, the Client decides whether
to opt into the task as described in {{provisioning-a-task}}. If the Client opts
out, it MUST NOT attempt to upload reports for the task.

Once the client opts into a task, it may begin uploading reports for the task to
the Leader.

Clients advertise the task configuration as specified in {{task-advertisement}}
in order to convey the task configuration to the Leader. If the Client does not
advertise the task configuration and the Leader does not already have it, then
the Leader will abort with error "unrecognizedTask". At this point, the Client
may retry the upload with the task advertisement.

## Leader Behavior

### Upload Protocol

Upon receiving a Client report, if the Leader does not support the {{taskprov}}
mechanism, it will ignore the DAP-Taskprov header. In particular, if the task
ID is not recognized, then it MUST abort the upload request with
"unrecognizedTask".

Otherwise, if the Leader does support this mechanism, it first checks if the
DAP-Taskprov header is present. If not present, that means the Client has
skipped task advertisement. If the Leader recognizes the task ID, it will
include the client report in the aggregation of that task ID. Otherwise, it
MUST abort with "unrecognizedTask". The Client will then retry with the task
advertisement.

If the Client advertises the task, the Leader checks that the task ID indicated
by the upload request matches the task ID derived from the DAP-Taskprov header
value. If the task ID does not match, then the Leader MUST abort with
"unrecognizedTask".

The Leader then decides whether to opt in to the task as described in
{{provisioning-a-task}}. If it opts out, it MUST abort the upload request with
"invalidTask".

Finally, once the Leader has opted in to the task, it completes the upload
request as usual.

### Aggregation Protocol

When the Leader opts in to a task, it SHOULD derive the VDAF verification key
for that task as described in {{vdaf-verify-key}}. The Leader MUST advertise
the task to the Helper in every request incident to the task as described in
{{task-advertisement}}.

### Collection Protocol

The Collector might create a collection job for a task provisioned by this
mechanism prior to opting into the task. In this case, the Leader would need to
abort the collect request with "unrecognizedTask". When it does so, it is up to
the Collector to retry its request.

> OPEN ISSUE: This semantics is awkward, as there's no way for the Leader to
> distinguish between Collectors who support this mechanism and those that don't.

The Leader MUST advertise the task in every aggregate share request issued to
the Helper as described in {{task-advertisement}}.

## Helper Behavior

The Leader advertises a task to the Helper during each step of an aggregation
job and when it requests the Helper's aggregate share during a collection job.

Upon receiving a task advertisement from the Leader, If the Helper does not
support this mechanism, it will ignore the DAP-Taskprov header and process the
request as usual. In particular, if the Helper does not recognize the task ID,
it MUST abort the request with error "unrecognizedTask". Otherwise, if the
Helper supports this mechanism, it proceeds as follows.

First, the Helper checks that the task ID indicated in the request matches the
task ID derived from the `TaskConfig` as defined in {{definition}}. If not, the
Helper MUST abort with "unrecognizedTask".

Next, the Helper decides whether to opt in to the task as described in
{{provisioning-a-task}}. If it opts out, it MUST abort the request with
"invalidTask".

Finally, the Helper completes the request as usual, deriving the VDAF
verification key for the task as described in {{vdaf-verify-key}}.

## Collector Behavior

Upon receiving a `TaskConfiguration` from the Author, the Collector first
decides whether to opt into the task as described in {{provisioning-a-task}}. If
the Collector opts out, it MUST NOT attempt to initialize collection jobs for
the task.

Otherwise, once opted in, the Collector MAY begin to issue collect requests for
the task. The task ID for each request MUST be derived from the
`TaskConfiguration` as described in {{provisioning-a-task}}. The Collector MUST
advertise the task as described in {{task-advertisement}}.

If the Leader responds to a collection request with an "unrecognizedTask"
error, the Collector MAY retry its request after waiting an appropriate
amount of time.

# Security Considerations

The Taskprov extension has the same security and privacy considerations as the
core DAP protocol. In addition, successful execution of a DAP task implies
agreement on the task configuration. This is provided by binding the
parameters to the task ID, which in turn is bound to each report uploaded for a
task. Furthermore, inclusion of the Taskprov extension in the task configuration
means Aggregators that do not implement this extension will reject the report as
required by {{Section 4.2.2 of !DAP}}.

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
Clients cannot forge task creation, e.g., via a task extension ({{Section 4.2.2
of !DAP}}).

Support for the Taskprov extension may render a deployment of DAP more
susceptible to task enumeration attacks ({{Section 8.6.1 of !DAP}}). For
example, if the Leader's upload endpoint is unauthenticated, then any HTTP
client can learn if a Leader supports a particular task configuration by
uploading a report for it with the Taskprov extension. Aggregators can mitigate
these kinds of attack by:

1. Requiring authentication of all APIs, including the upload endpoint (see
   {{Section 3.5 of !DAP}});

1. Enforcing rate limits on unauthenticated APIs; or

1. Including entropy in the `task_info` field of the `TaskConfiguration` in
   order to make the task ID harder to predict (e.g., 16 bytes of output of a
   CSPRNG).

# Operational Considerations

The Taskprov extension does not introduce any new operational considerations
for DAP.

The task provisioning mechanism in {{taskprov}} is designed so that the
Aggregators do not need to store individual task configurations long-term.
Because the task configuration is advertised in each request in the upload,
aggregation, and collection protocols, the process of opting-in and deriving the
task ID and VDAF verify key can be re-run on the fly for each request. This is
useful if a large number of concurrent tasks are expected. Once an Aggregator
has opted-in to a task, the expectation is that the task is supported until it
ends. In particular, Aggregators that operate in this manner MUST NOT opt
out once they have opted in.

# IANA Considerations

This document requests a codepoint for the `taskprov` task extension.

(RFC EDITOR: Replace "XXXX" with the RFC number assigned to this document.)

## Task Extension

The following entry will be (RFC EDITOR: change "will be" to "has been") added
to the "DAP Task Extension Identifiers" registry of the "Distributed Aggregation
Protocol (DAP)" page created by {{!DAP}}:

Value:
: `0x0002`

Name:
: `taskprov`

Reference:
: {{definition}} of RFC XXXX

## DAP Sub-namespace for DAP

> TODO Figure out how to ask IANA to register the errors in
> {{urn-space-errors}}. See
> https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap-taskprov/issues/34

## HTTP Field Name Registration

A new entry to the "Hypertext Transfer Protocol (HTTP) Field Name Registry"
will be (RFC EDITOR: change "will be" to "has been") added for the task
advertisement header ({{task-advertisement}}):

| Field Name   | Status    | Structured Type | Reference                |
|:-------------|:----------|:----------------|:-------------------------|
| DAP-Taskprov | permanent | Item            | {{taskprov}} of RFC XXXX |
{: #http-header title="Updates to the Hypertext Transfer Protocol (HTTP) Field Name Registry"}

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

Tim Geoghegan
ISRG
timgeog+ietf@gmail.com

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
