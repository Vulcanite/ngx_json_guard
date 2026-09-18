# Roadmap

Growth work after the v0.1.0 ship. None of this is implemented yet.

## Live validation via `ngx_http_request_body_filter`

The module currently waits until NGINX has finished reading or spooling
the body, then walks those buffers. That is post-read validation: a
malformed 20 MiB document is fully received before the 400 goes out, and
the walk itself is a blocking `ngx_read_file` on the worker. A request
body filter that feeds chunks as they arrive would reject early, overlap
validation with upload, and turn the README's "not live" disclaimer into
the actual feature.

## `json_guard_max_file_body`

Until live validation exists, a spooled body still stalls the worker for
the duration of the temp-file walk. A size threshold that skips
validation (and logs) above a configured limit bounds that stall so a
single huge upload cannot pin the event loop. It is a stopgap, not a
substitute for streaming rejection.

## Top-level required-key allowlist

Shape limits today are numeric (depth, widths, token counts). A small
allowlist of required top-level keys would catch empty objects and
wrong-schema posts without becoming a JSON Schema engine. It is the
cheapest step from "well-formed" toward "this looks like our API."

## `$json_guard_depth` / `$json_guard_members`

`$json_guard_inspection_us` already exposes cost. Depth and member counts
on the same request would make access logs and metrics explain *why* a
413 fired, and would let operators tune limits from production traffic
instead of guessing. Both values are already sitting in parser state;
they just are not exported.
