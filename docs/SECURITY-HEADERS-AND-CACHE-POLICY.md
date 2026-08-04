# Security Headers and Cache Policy

File 24 private administration and non-public governance REST responses use `private, no-store` and `noindex` controls. Public responses receive conservative baseline headers without globally disabling platform capabilities owned by other modules.

File 24 does **not** impose a site-wide `Permissions-Policy` that disables camera, microphone or geolocation, because Communication Network and Video/Live modules retain native ownership of those browser capabilities. Native owners may provide an approved policy through the versioned `spcrc/security_headers/permissions_policy` filter after their own authorization, consent and feature checks.

Headers do not replace object authorization, secure coding, native-module policy, infrastructure controls or cache-key separation. Public Trust Center responses remain separately minimized and cache-governed.
