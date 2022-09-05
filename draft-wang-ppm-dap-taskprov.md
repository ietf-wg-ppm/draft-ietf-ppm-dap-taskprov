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
    organization: Apple
    email: "shan_wang@apple.com"
 -
    fullname: Christopher Patton
    organization: Cloudflare
    email: "cpatton@cloudflare.com"

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
many deployments.

> TODO(wangshan) Describe the goals of this mechanism, including the deployment
> scenario. Then describe how the extension works at a high level. I think the
> intro should answer the following questions:
>
> - Why does this mechanism need to be an extension (i.e., why are protocol
>   changes needed), as opposed to something that happens completely
>   out-of-band?
>
> - Which of the sub-protocols are changed: upload, aggregate, collect?

> TODO: talk about client logging task configuration and checking against
parameters like task_expiration.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


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

When the Client includes this extension with its report, the body of the
extension is structured as follows:

~~~
/* Definition of all parameters in extension_data for one task */
struct {
  /* Info specific for a task. */
  opaque task_info<1..2^8-1>,

  /* A list of URLs relative to which an aggregator's API endpoints can be found. */
  opaque aggregator_endpoints<1..2^16-1>,

  /* This determines the query type for batch selection and the properties that all batches for this task must have. */
  QueryConfig query_config,

  /* The maximum number of times a batch of reports may be queried by the Collector. */
  uint16 max_batch_lifetime,

  /* [[OPEN ISSUE: https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/pull/304]] */
  Time task_expiration,

  /* A unique identifier for the VDAF instance used for the task, including the type of measurement associated with the task. */
  VdafType vdaf_type,

  /* Additional parameters relevant for the vdaf_type */
  opaque vdaf_data<1..2^16-1>,
} TaskConfig;

/* Defined in DAP core protocol */
/* https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/blob/main/draft-ietf-ppm-dap.md#queries-query */
enum {
   reserved(0), // Reserved for testing purposes
   time-interval(1),
   fixed-size(2),
   (65535)
} QueryType;

struct {
  uint32 max_batch_size,
} FixedSizeQueryConfig;

struct {
  QueryType query_type,
  Duration time_precision,
  uint32 min_batch_size,
  select (query_type) {
    case time-interval: Empty;
    case fixed-size: FixedSizeQueryConfig fixed_size_query_config;
  }
} QueryConfig;
~~~

The purpose of `TaskConfig` is to include all parameters that are
necessary for creating a new task in aggregator. It includes all the fields to
be associated with a task (see task configuration in
{{?DAP=I-D.draft-ietf-ppm-dap}}.). Besides, `TaskConfig` also includes fields
that useful for configuring a task in-band:

* An opaque `task_info` that is specific to a task. For e.g. this can be a
string describing the purpose of this task.

* An opaque `vdaf_data` that contains any VDAF specific parameters for the
chosen `vdaf_type`. The aggregators MUST pass `vdaf_data` to VDAF initialiser,
based on the chosen `vdaf_type`.

~~~
/* Below are NOT in taskprov, used for Apple-CF deployment. */
/* To be deleted from task-prov extension, but is ok to have trace in public */
/* repo since all algorithms described below have been published. */

/* INAN codepoints for VDAF */
/* https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/blob/main/draft-ietf-ppm-dap.md#queries-query */
/* NOTE(cjpatton) CamelCase is different from other enums values in DAP world. */
enum {
  Prio3Aes128Count(0x00000000),
  Prio3Aes128Sum(0x00000001),
  Prio3Aes128Histogram(0x00000002),
  /* 0x00000003 to 0x00000FFF reserved for Prio3 */
  Poplar1Aes128(0x00001000),
  /* 0xFFFF0000 to 0xFFFFFFFF reserved for private use */
  Prio2(0xFFFF0000),
  /* 0xFFFF0001 to 0xFFFF0003 reserved for Prio2 */
  PrioPlusPlus(0xFFFF0004),
  /* 0xFFFF0005 to 0xFFFF0007 reserved for PrioPlusPlus */
  PrioPiRappor(0xFFFF0008),
  /* 0xFFFF0009 to 0xFFFF000F reserved for PiRappor */
  (255)
} VdafType;

enum {
  reserved(0), // Reserved for testing purposes
  float16(1),
  float32(2),
  float64(3),
  fixed-point16(4),
  fixed-point32(5),
  fixed-point64(6),
  (7)
} RealNumberType;

struct {
  RealNumberType real_number_type;
  select (real_number_type) {
    case float16: uint16 float16_num;
    case float32: uint32 float32_num;
    case float64: uint64 float64_num;
    case fixed-point16: uint16 fixed_point16_num;
    case fixed-point32: uint32 fixed_point32_num;
    case fixed-point64: uint64 fixed_point64_num;
  }
} RealNumber;

/* Encoded VdafParameters is in vdaf_data */
struct {
  uint32 dimension;
  RealNumber epsilon;
  select (vdaf_type) { // determined by TaskConfig vdaf_type
    case Prio2: Empty;
    case Prio3: Empty;
    case PrioPlusPlus: PrioPlusPlusParams
    case PrioPiRappor: PrioPiRapporParams
  }
} VdafParameter;

struct {
  RealNumber sigma;
} PrioPlusPlusParams;

struct {
  uint32 prime;
  RealNumber alpha0;
  RealNumber alpha1;
} PrioPiRapporParams;
~~~


# Client Behavior

> TODO(wangshan) Say how the Client constructs the extension body. Does the
> extension change anything else about the upload flow?

The client should know whether task-prov extension will be used and all
parameters required for `TaskConfig` prior to constructing the extension
body, either out-of-band from aggregators, or from information already saved on
client.

## Construct task ID

To use this extension, the client should first decide what is the task ID. For
task-prov extension, a DAP task is not created before distributing task
configuration to clients. Therefore, a DAP task ID may not be available to
clients or aggregators before uploading. Aggregator MAY still choose a task ID
for this task and deliver it to all clients in `task_info`. In this case,
client MUST use that `task_info` as task ID. This arrangement SHOULD be agreed
by aggregators and clients out-of-band.

Alternatively, client can construct the task ID from `task_info` and any other
part of task configuration, as long as the generated task ID is determinstic and
stay consistent across all devices.

## Construct extension body

Client constructs this extension during the upload flow, after hpke config
(see update flow and hpke-config in {{?DAP=I-D.draft-ietf-ppm-dap}}.). Note
that if task ID is not available at time of hpke config query, the client
should use `[aggregator]/hpke_config` API without specifying a `task_id`.
Client typically sets `extension_type` to `task-prov` codepoint in
`ReportMetadata`'s extenion field, and save the encoded `TaskConfig` in
`extension_data` field.


# Leader Behavior

> TODO(wangshan) Say what the Leader does when it receives a report with this
> extension. What do Leaders do if they *don't* support this extension? Is it
> safe to ignore it? How are the upload, aggregate, and collect flows impacted?


# Helper Behavior

> TODO(wangshan) Say what the Helper does when it receives a report share with
> this extension. (Same questions as above.)


# Collector Behavior

> TODO(wangshan) Describe if/how this extension impacts Collector behavior.


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
