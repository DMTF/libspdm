# libspdm Requester API

## Introduction
This document details the public API available to Integrators when constructing an SPDM Requester
using libspdm.

## Functions
---
### libspdm_send_request
---
#### Description
Sends an SPDM request message to an endpoint.

#### Parameters asdasdsad

**spdm_context**<br/>
The SPDM context.<br/>

**session_id**<br/>
Indicates if the request is a secured message (non-NULL) or unsecured message (NULL).<br/>

**is_app_message**<br/>
Indicates if the message is an application message (true) or an SPDM message (false).

**request_size**<br/>
Size in bytes to be sent to the endpoint.<br/>
