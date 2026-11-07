%%% @doc Test helper: the CRL fixtures under fixtures/crl/ (see its README).
-module(yuzu_gw_crl_fixture).

-export([path/1, read/1, cert_der/1, server_serial/0]).

%% @doc The absolute path of a fixture file.
-spec path(string()) -> file:filename().
path(Name) ->
    filename:join([filename:dirname(?FILE), "fixtures", "crl", Name]).

-spec read(string()) -> binary().
read(Name) ->
    {ok, Bin} = file:read_file(path(Name)),
    Bin.

%% @doc The DER of the first certificate in a PEM fixture.
-spec cert_der(string()) -> binary().
cert_der(Name) ->
    [{'Certificate', Der, not_encrypted} | _] = public_key:pem_decode(read(Name)),
    Der.

%% @doc The serial of server.pem as the integer a CRL entry carries.
-spec server_serial() -> pos_integer().
server_serial() ->
    binary_to_integer(string:trim(read("server.serial")), 16).
