// Package mcp is a dependency-free stdio JSON-RPC 2.0 MCP server over the
// shared engine, answering lookup_ioc, search_threats, get_entity,
// get_related, get_reports, server_status and get_usage.
//
// This package is where the response budget lives. The engine returns complete
// views; what one tool result may cost is decided here. Two backstops sit at
// the boundary (budget.go, server.go): any string over 1000 characters that is
// not carried whole by design (a description, a pattern) is shortened and
// named, and no result leaves over 128 KB — a lookup or a search loses items
// from its tail, named in notes; a paged list is refused, because dropping
// rows would make its cursor skip them. Nothing is spilled to a file: the
// calling runtime does that (organization ADR-021 §3).
//
// get_usage is canonical: the embedded manual is what an agent reads before
// its first call, and meta-tests pin it to the code. Tool errors are
// structured JSON ({code, message}), returned as results rather than protocol
// errors so that the model sees them. Tool text states triggers, contracts and
// provenance; it carries no defensive instructions — that layer belongs to the
// runtime.
//
// Arguments are decoded strictly (decodeArgs): an undeclared argument is
// refused by name, for every tool including those that take none.
//
// A closing stdin is the shutdown signal. An MCP cancellation notification may
// be ignored by its receiver, so nothing here depends on one arriving.
package mcp
