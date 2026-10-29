%%%-------------------------------------------------------------------
%%% @doc What is wrong with the files an upstream endpoint's TLS options name.
%%%
%%% An `https' endpoint names a CA file (`cacertfile'), usually a client
%%% certificate (`certfile') and key (`keyfile'). When one of them is missing, is
%%% a directory, is empty, or holds no certificate, `ssl' rejects the whole
%%% option set, every connection attempt fails in about two milliseconds with the
%%% one word `bad_tls_options', and nothing says which file or why. This module
%%% finds out, so the boot guard, the channel's error log and /readyz can say it.
%%%
%%% It looks; it never decides. A missing file is NOT a boot refusal anywhere: the
%%% server generates its certificates on first start, which can be after the
%%% gateway's, and the channel keeps retrying until the file appears. A directory
%%% where a file belongs is different (see `directory'): it can never become one.
%%%
%%% Reasons, as atoms:
%%%   enoent          the file does not exist (yet)
%%%   eacces          the gateway's user may not read it
%%%   directory       the path is a directory. A container runtime creates one
%%%                   when a bind-mounted file is missing on the host
%%%   not_regular     a socket, device or other non-file
%%%   empty           zero bytes
%%%   no_certificate  `cacertfile'/`certfile' holds no PEM certificate
%%%   no_key          `keyfile' holds no PEM private key
%%%   Posix           any other file error, as the POSIX atom (`eio', ...)
%%%
%%% Paths: a `cacertfile' or `certfile' path is a public certificate's location
%%% and is returned so a log line can name it. A `keyfile' path is NEVER
%%% returned (`undefined' in its place): nothing here can leak it into a log by
%%% accident, and the operator knows which key their config names.
%%%
%%% A file over 4 MiB is not parsed; it is reported fine if it is a regular file.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_tls_files).

-include_lib("kernel/include/file.hrl").

-export([diagnose/1, diagnose_endpoint/1, describe/1, has_definite_defect/1]).
-export_type([problem/0, reason/0]).

-define(MAX_PARSE_BYTES, 4 * 1024 * 1024).

-type reason() :: enoent | eacces | directory | not_regular | empty
                | no_certificate | no_key | atom().
-type problem() :: {cacertfile | certfile | keyfile, string() | undefined, reason()}.

%% @doc The problems of one endpoint's TLS files; none for a plaintext endpoint.
-spec diagnose_endpoint(yuzu_grpc_client_config:endpoint()) -> [problem()].
diagnose_endpoint(#{transport := tls, tls_opts := Opts}) when is_list(Opts) ->
    diagnose(Opts);
diagnose_endpoint(_) ->
    [].

%% @doc The problems of an `ssl' client option list, in the order cacertfile,
%% certfile, keyfile. An option that is absent, or is not a path, is not checked.
-spec diagnose([term()]) -> [problem()].
diagnose(Opts) ->
    lists:append([check(Key, proplists:get_value(Key, Opts)) || Key <- [cacertfile, certfile, keyfile]]).

%% @doc True when a problem can never clear by waiting: a directory or a
%% non-file at the path. Used by the boot guard, which refuses only on these.
-spec has_definite_defect([problem()]) -> boolean().
has_definite_defect(Problems) ->
    lists:any(fun({_, _, R}) -> R =:= directory orelse R =:= not_regular end, Problems).

%% @doc One problem as text for a log line.
-spec describe(problem()) -> string().
describe({Key, Path, Reason}) ->
    lists:flatten(io_lib:format("~s~s ~s", [Key, shown(Path), reason_text(Key, Reason)])).

shown(undefined) -> "";
shown(Path)      -> [$\s | Path].

reason_text(_, enoent)         -> "does not exist (yet)";
reason_text(_, eacces)         -> "cannot be read (permission denied)";
reason_text(_, directory)      -> "is a directory, not a file";
reason_text(_, not_regular)    -> "is not a regular file";
reason_text(_, empty)          -> "is empty";
reason_text(_, no_certificate) -> "contains no PEM certificate";
reason_text(_, no_key)         -> "contains no PEM private key";
reason_text(_, Posix)          -> lists:flatten(io_lib:format("cannot be read (~s)", [Posix])).

check(_Key, undefined) ->
    [];
check(Key, Path0) ->
    case path(Path0) of
        undefined -> [];
        Path      -> problems(Key, Path)
    end.

path(P) when is_binary(P), P =/= <<>> -> path(binary_to_list(P));
path(P) when is_list(P), P =/= [] ->
    case io_lib:printable_unicode_list(P) of
        true  -> P;
        false -> undefined
    end;
path(_) -> undefined.

problems(Key, Path) ->
    Shown = case Key of keyfile -> undefined; _ -> Path end,
    case content(Key, Path) of
        ok     -> [];
        Reason -> [{Key, Shown, Reason}]
    end.

content(Key, Path) ->
    case file:read_file_info(Path) of
        {ok, #file_info{type = directory}} -> directory;
        {ok, #file_info{type = regular, size = 0}} -> empty;
        {ok, #file_info{type = regular, size = Size}} when Size > ?MAX_PARSE_BYTES -> ok;
        {ok, #file_info{type = regular}} -> parse(Key, Path);
        {ok, #file_info{}} -> not_regular;
        {error, Posix} -> Posix
    end.

parse(Key, Path) ->
    case file:read_file(Path) of
        {ok, Bin}      -> entries(Key, pem(Bin));
        {error, Posix} -> Posix
    end.

pem(Bin) ->
    try public_key:pem_decode(Bin) catch _:_ -> [] end.

entries(keyfile, Entries) ->
    case [E || {Type, _, _} = E <- Entries, Type =/= 'Certificate'] of
        [] -> no_key;
        _  -> ok
    end;
entries(_Cert, Entries) ->
    case [E || {'Certificate', _, _} = E <- Entries] of
        [] -> no_certificate;
        _  -> ok
    end.
