%%%-------------------------------------------------------------------
%%% @doc The method table of one listener: "/pkg.Service/Method" -> the
%%% service function that answers it. Pure; built once when the listener
%%% starts.
%%%
%%% A listener is configured with the gpb modules that describe its services
%%% (`service_protos') and a map from service name to the module that
%%% implements it (`services'). A method is routed to the arity-2 function
%%% named like the method in snake_case (ListAgents -> list_agents/2, the
%%% convention grpcbox used). A method whose function the module does not
%%% export is simply absent from the table, which a request reads as
%%% UNIMPLEMENTED -- except that a service none of whose methods the module
%% exports is refused (`{service_without_routes, Service}'), since a listener
%% that serves a service nothing answers is a misconfiguration (a mistyped
%% module), not a partial implementation. A gpb module may describe services it does not own (the
%%% management proto imports the agent one), so only the services named in
%%% `services' are routed.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_route).

-export([build/2, lookup/2, snake_case/1]).

-export_type([route/0, table/0, kind/0]).

-type kind() :: unary | server_stream | client_stream | bidi.
-type route() :: #{path := binary(),
                   module := module(),
                   function := atom(),
                   kind := kind(),
                   pb := module(),
                   input := atom(),
                   output := atom()}.
-type table() :: #{binary() => route()}.

%% @doc The table for a listener, or why it cannot be built: a service named in
%% `Services' that no proto describes, or an implementing module that cannot be
%% loaded, or a service for which the module exports none of its methods.
-spec build([module()], #{atom() => module()}) -> {ok, table()} | {error, term()}.
build(Protos, Services) when is_list(Protos), is_map(Services) ->
    try
        {ok, lists:foldl(fun({Service, Module}, Acc) ->
                                 service_routes(Protos, Service, Module, Acc)
                         end, #{}, lists:sort(maps:to_list(Services)))}
    catch
        throw:{route_error, Reason} -> {error, Reason}
    end.

%% @doc The route of a request path, or `error' (UNIMPLEMENTED).
-spec lookup(binary(), table()) -> {ok, route()} | error.
lookup(Path, Table) ->
    maps:find(Path, Table).

%% @doc A method name as the function that answers it: ListAgents ->
%% list_agents, QueryInventory -> query_inventory.
-spec snake_case(atom()) -> atom().
snake_case(Name) ->
    Snaked = lists:foldl(fun(RE, Acc) ->
                                 re:replace(Acc, RE, "\\1_\\2", [{return, list}, global])
                         end, atom_to_list(Name),
                         ["(.)([A-Z][a-z]+)", "(.)([0-9]+)", "([a-z0-9])([A-Z])"]),
    list_to_atom(string:to_lower(lists:flatten(string:replace(Snaked, ".", "_", all)))).

%%--------------------------------------------------------------------

service_routes(Protos, Service, Module, Table) ->
    Pb = proto_of(Protos, Service),
    Exports = exports_of(Module),
    Added = lists:foldl(fun(Rpc, Acc) ->
                                method_route(Pb, Service, Module, Exports, Rpc, Acc)
                        end, #{}, Pb:get_rpc_names(Service)),
    case map_size(Added) of
        0 -> throw({route_error, {service_without_routes, Service}});
        _ -> maps:merge(Table, Added)
    end.

method_route(Pb, Service, Module, Exports, Rpc, Table) ->
    Function = snake_case(Rpc),
    case lists:member({Function, 2}, Exports) of
        false ->
            Table;
        true ->
            #{input := Input, output := Output,
              input_stream := InStream, output_stream := OutStream} = Pb:find_rpc_def(Service, Rpc),
            Path = <<"/", (atom_to_binary(Service, utf8))/binary,
                     "/", (atom_to_binary(Rpc, utf8))/binary>>,
            Table#{Path => #{path => Path, module => Module, function => Function,
                             kind => kind(InStream, OutStream), pb => Pb,
                             input => Input, output => Output}}
    end.

kind(false, false) -> unary;
kind(false, true) -> server_stream;
kind(true, false) -> client_stream;
kind(true, true) -> bidi.

proto_of(Protos, Service) ->
    case [Pb || Pb <- Protos, lists:member(Service, Pb:get_service_names())] of
        [Pb | _] -> Pb;
        [] -> throw({route_error, {unknown_service, Service}})
    end.

exports_of(Module) when is_atom(Module) ->
    case code:ensure_loaded(Module) of
        {module, Module} -> Module:module_info(exports);
        {error, _} -> throw({route_error, {module_not_loaded, Module}})
    end;
exports_of(Module) ->
    throw({route_error, {module_not_loaded, Module}}).
