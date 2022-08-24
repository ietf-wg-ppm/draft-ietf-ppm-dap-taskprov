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
    fullname: Your Name Here
    organization: Your Organization Here
    email: "shan_wang@apple.com"

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


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# The "task_prov" Extension

> NOTE(cjpatton) It will be useful to think of a good name for this. Something
> succinct and descriptive is ideal. `task_prov` is fine, but we can maybe do
> better.

A new extension is defined:

~~~
enum {
   task_prov(0xff00), (65535)
} ExtensionType;
~~~

When the Client includes this extension with its report, the body of the
extension is structured as follows:

~~~
TODO(wangshan) Specify the structure of the extension.
~~~


# Client Behavior

> TODO(wangshan) Say how the Client constructs the extension body. Does the
> extension change anything else about the upload flow?


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
