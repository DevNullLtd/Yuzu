// Run with /usr/bin/osascript -l JavaScript. Uses only macOS Foundation;
// installation does not require Python, Xcode, a shell eval, or GUI automation.
ObjC.import('Foundation');

function readPlist(path) {
    const data = $.NSData.dataWithContentsOfFile(path);
    if (!data) throw new Error('Cannot read plist');
    const error = Ref();
    const value = $.NSPropertyListSerialization.propertyListWithDataOptionsFormatError(data, 0, null, error);
    if (!value) throw new Error('Cannot decode plist');
    return ObjC.deepUnwrap(value);
}

function merge(prior, generated, forceNoAutoUpdate) {
    const oldArgs = prior.ProgramArguments;
    const newArgs = generated.ProgramArguments;
    function stringArray(value) {
        return Array.isArray(value) && value.length > 0 && value.every(x => typeof x === 'string');
    }
    if (!stringArray(oldArgs) || !stringArray(newArgs)) throw new Error('Invalid ProgramArguments');
    const fixed = ['--plugin-dir', '--data-dir', '--log-file', '--log-max-size', '--log-max-files'];
    const signing = ['--plugin-trust-bundle', '--plugin-require-signature'];
    const generatedSigning = newArgs.indexOf('--plugin-trust-bundle') >= 0;
    const preserved = [];
    for (let index = 1; index < oldArgs.length;) {
        const argument = oldArgs[index];
        const name = argument.split('=', 1)[0];
        const inlineValue = argument.indexOf('=') >= 0;
        if (fixed.indexOf(name) >= 0) {
            index += inlineValue ? 1 : 2;
        } else if (name === '--no-auto-update' && forceNoAutoUpdate) {
            index += 1;
        } else if (generatedSigning && signing.indexOf(name) >= 0) {
            index += name === '--plugin-trust-bundle' && !inlineValue ? 2 : 1;
        } else {
            preserved.push(argument);
            index += 1;
        }
    }
    generated.ProgramArguments = newArgs.concat(preserved);
    // Every operator-set YUZU_* key survives an upgrade (OTA signing, inventory
    // and licence opt-outs included), as do proxy settings. Dropped: keys the
    // generated definition forces, and anything else, each named on stderr
    // (PR #4482 governance er-2).
    const forced = ['YUZU_PLUGIN_DIR', 'YUZU_DATA_DIR'];
    if (generatedSigning) forced.push('YUZU_PLUGIN_TRUST_BUNDLE', 'YUZU_PLUGIN_REQUIRE_SIGNATURE');
    const proxies = ['http_proxy', 'https_proxy', 'no_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY',
        'grpc_proxy'];
    function stringMap(value, what) {
        if (value === undefined) return {};
        if (!value || Array.isArray(value) || typeof value !== 'object' ||
            !Object.keys(value).every(key => typeof value[key] === 'string')) {
            throw new Error('Invalid ' + what + ' EnvironmentVariables');
        }
        return value;
    }
    const oldEnvironment = stringMap(prior.EnvironmentVariables, 'previous');
    const retained = Object.assign({}, stringMap(generated.EnvironmentVariables, 'generated'));
    Object.keys(oldEnvironment).forEach(key => {
        if (forced.indexOf(key) >= 0 || Object.prototype.hasOwnProperty.call(retained, key)) {
            console.log('merge-launchd-plist: not retaining ' + key + ': set by the package');
        } else if (key.indexOf('YUZU_') === 0 || proxies.indexOf(key) >= 0) {
            retained[key] = oldEnvironment[key];
        } else {
            console.log('merge-launchd-plist: not retaining ' + key + ': not a Yuzu or proxy setting');
        }
    });
    if (Object.keys(retained).length) generated.EnvironmentVariables = retained;
    else delete generated.EnvironmentVariables;
    return generated;
}

function run(argv) {
    let previous, destination, force = false;
    for (let index = 0; index < argv.length; index++) {
        if (argv[index] === '--previous') previous = argv[++index];
        else if (argv[index] === '--destination') destination = argv[++index];
        else if (argv[index] === '--force-no-auto-update') force = true;
        else throw new Error('Unknown argument');
    }
    if (!previous || !destination) throw new Error('Previous and destination plist paths required');
    const generated = readPlist(destination);
    let prior;
    try {
        prior = readPlist(previous);
        const args = prior.ProgramArguments, env = prior.EnvironmentVariables;
        if (!Array.isArray(args) || args.length === 0 || !args.every(x => typeof x === 'string'))
            throw new Error('invalid ProgramArguments');
        if (env !== undefined && (!env || Array.isArray(env) || typeof env !== 'object' ||
            !Object.keys(env).every(key => typeof env[key] === 'string')))
            throw new Error('invalid EnvironmentVariables');
    } catch (error) {
        // An unparseable live definition (a hand-edit typo, a torn write) must not
        // wedge every upgrade: install the package default, as before this merge
        // existed, and say so (PR #4482 governance ch-1).
        console.log('merge-launchd-plist: WARNING: the existing service definition cannot be read (' +
            error.message + '); installing the package default, so earlier --server and other ' +
            'settings must be re-applied');
        return;
    }
    const result = merge(prior, generated, force);
    const error = Ref();
    const data = $.NSPropertyListSerialization.dataWithPropertyListFormatOptionsError(
        $(result), $.NSPropertyListXMLFormat_v1_0, 0, error);
    if (!data || !data.writeToFileAtomically(destination, true)) throw new Error('Cannot write merged plist');
}
