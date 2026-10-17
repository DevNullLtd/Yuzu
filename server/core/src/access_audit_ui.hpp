#pragma once

/// @file access_audit_ui.hpp
/// The Audit and reviews page HTML. `kAccessAuditTemplate` is the page before the shell is
/// baked in (exposed so tests can inspect the literal); `kAccessAuditHtml` is what
/// `GET /access/audit` serves. Every panel fills itself by htmx.

extern const char* const kAccessAuditTemplate;
extern const char* const kAccessAuditHtml;
