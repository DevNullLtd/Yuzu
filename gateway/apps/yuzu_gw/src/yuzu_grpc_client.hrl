%%% gRPC status codes as the CLIENT sees them: the `grpc-status' trailer is a
%%% decimal binary string, and yuzu_grpc_client returns it as such
%%% (`{error, {<<"9">>, Message}, Meta}'). The server layer's yuzu_grpc.hrl
%%% defines the same codes as integers under `GRPC_STATUS_*'; these carry
%%% `_BIN_' so the two can never be mistaken for one another.
-define(GRPC_STATUS_BIN_OK,                  <<"0">>).
-define(GRPC_STATUS_BIN_CANCELLED,           <<"1">>).
-define(GRPC_STATUS_BIN_UNKNOWN,             <<"2">>).
-define(GRPC_STATUS_BIN_INVALID_ARGUMENT,    <<"3">>).
-define(GRPC_STATUS_BIN_DEADLINE_EXCEEDED,   <<"4">>).
-define(GRPC_STATUS_BIN_NOT_FOUND,           <<"5">>).
-define(GRPC_STATUS_BIN_ALREADY_EXISTS,      <<"6">>).
-define(GRPC_STATUS_BIN_PERMISSION_DENIED,   <<"7">>).
-define(GRPC_STATUS_BIN_RESOURCE_EXHAUSTED,  <<"8">>).
-define(GRPC_STATUS_BIN_FAILED_PRECONDITION, <<"9">>).
-define(GRPC_STATUS_BIN_ABORTED,             <<"10">>).
-define(GRPC_STATUS_BIN_OUT_OF_RANGE,        <<"11">>).
-define(GRPC_STATUS_BIN_UNIMPLEMENTED,       <<"12">>).
-define(GRPC_STATUS_BIN_INTERNAL,            <<"13">>).
-define(GRPC_STATUS_BIN_UNAVAILABLE,         <<"14">>).
-define(GRPC_STATUS_BIN_DATA_LOSS,           <<"15">>).
-define(GRPC_STATUS_BIN_UNAUTHENTICATED,     <<"16">>).
