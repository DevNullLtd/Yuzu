%%% gRPC status codes, the stream handle a service handler receives, and the
%%% default limits of the yuzu_grpc layer (see yuzu_grpc_stream_h).
%%%
%%% Statuses are integers 0..16. A handler may also return the decimal binary
%%% form (<<"5">>): yuzu_grpc_frame:normalize_status/1 accepts both. Do NOT
%%% include this file next to grpcbox/include/grpcbox.hrl: the macro names are
%%% the same and their values differ (binaries there, integers here).

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
