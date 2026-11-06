%%% gRPC status codes, the stream handle a service handler receives, and the
%%% default limits of the yuzu_grpc layer (see yuzu_grpc_stream_h).
%%%
%%% Statuses are integers 0..16. A handler may also return the decimal binary
%%% form (<<"5">>): yuzu_grpc_frame:normalize_status/1 accepts both. The
%%% client side (yuzu_grpc_client) returns the status as a decimal binary and has
%%% its own codes in yuzu_grpc_client.hrl under GRPC_STATUS_BIN_*: the names
%%% differ so the two can be included together and never be mistaken.

-define(GRPC_STATUS_OK, 0).
-define(GRPC_STATUS_CANCELLED, 1).
-define(GRPC_STATUS_UNKNOWN, 2).
-define(GRPC_STATUS_INVALID_ARGUMENT, 3).
-define(GRPC_STATUS_DEADLINE_EXCEEDED, 4).
-define(GRPC_STATUS_NOT_FOUND, 5).
-define(GRPC_STATUS_ALREADY_EXISTS, 6).
-define(GRPC_STATUS_PERMISSION_DENIED, 7).
-define(GRPC_STATUS_RESOURCE_EXHAUSTED, 8).
-define(GRPC_STATUS_FAILED_PRECONDITION, 9).
-define(GRPC_STATUS_ABORTED, 10).
-define(GRPC_STATUS_OUT_OF_RANGE, 11).
-define(GRPC_STATUS_UNIMPLEMENTED, 12).
-define(GRPC_STATUS_INTERNAL, 13).
-define(GRPC_STATUS_UNAVAILABLE, 14).
-define(GRPC_STATUS_DATA_LOSS, 15).
-define(GRPC_STATUS_UNAUTHENTICATED, 16).

%% Largest request message the layer buffers (4 MiB, the gRPC default).
-define(YUZU_GRPC_MAX_MESSAGE_BYTES, 4194304).
%% How long yuzu_grpc_stream:send/2 waits for the connection process to take
%% a frame before it gives up with UNAVAILABLE.
-define(YUZU_GRPC_SEND_TIMEOUT_MS, 30000).
%% How long a unary or server-streaming stream may stay in `awaiting_request'
%% (buffering its one request, no handler running yet) before it is aborted with
%% DEADLINE_EXCEEDED and its buffer dropped. Bounds a peer that opens a stream,
%% sends all but the last byte of a large message and then stalls, holding the
%% buffer for as long as the connection lives (limits.request_timeout_ms;
%% `infinity' disables it).
-define(YUZU_GRPC_REQUEST_TIMEOUT_MS, 30000).
%% The per-connection memory ceiling the stream handler sets on the Cowboy
%% connection process (process_flag(max_heap_size), counting shared binaries, so
%% the refc buffers of its streams' in-flight requests are included). Default
%% when limits.max_connection_memory_bytes is unset: eight times the max message
%% size (32 MiB with the 4 MiB default; `infinity' disables it). Sized from what
%% the ceiling was measured to see: one message of max_message_bytes costs the
%% connection three times its size at its peak (its chunks, the joined message
%% and the decoded request) plus under a MiB of garbage, so two such messages
%% completing at once fit with room to spare (6x), and a flood of half-finished
%% streams, each holding its own size, is killed at about the eighth.
-define(YUZU_GRPC_MAX_CONN_MEMORY_FACTOR, 8).
%% The derived default never goes below this: with a small max_message_bytes,
%% eight times it could fall under a connection process's own baseline memory and
%% kill every connection at once. An EXPLICIT max_connection_memory_bytes must
%% also be at least this (or `infinity'); the listener refuses a smaller one.
-define(YUZU_GRPC_MIN_CONN_MEMORY_BYTES, 1048576).

%% The handle a service handler receives as its `Stream' argument. Opaque to
%% handlers: use the yuzu_grpc_stream and yuzu_grpc accessors, never the fields.
-record(yuzu_grpc_stream, {
    conn        :: pid(),           %% the Cowboy connection process
    stream_id   :: term(),          %% the HTTP/2 stream id
    ctx         :: ctx:t(),
    method      :: binary(),        %% "/pkg.Service/Method", for logs only
    pb          :: module(),        %% the gpb module that encodes responses
    output      :: atom(),          %% the response message type
    send_timeout = ?YUZU_GRPC_SEND_TIMEOUT_MS :: timeout()
}).
