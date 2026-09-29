#Requires -Version 7

$script:SupportedSchema = 'yuzu/windows-toolchain/v1'
$script:V1Pins = @('python','meson','erlang','rebar3','postgres','windows_sdk')
$script:V1JobPins = @('vcpkg_baseline')
$script:V1Environment = @('CCACHE_DIR','RUNNER_TOOL_CACHE','YUZU_ESCRIPT','YUZU_REBAR3','YUZU_TEST_POSTGRES_DSN')
$script:V1Tools = @('python','meson','ninja','cmake','git','ccache','escript','rebar3','msvc','msys2_bash','postgres','windows_sdk_header','windows_sdk_lib','windows_sdk_rc')
$script:V1ArtifactProbes = @('windows_sdk_header','windows_sdk_lib','windows_sdk_rc')
$script:V1EffectiveCommands = @('python','meson','git')
$script:V1ToolProbes = @('python','meson','rebar3','postgres')
$script:V1FileProbes = @('Erlang OTP')

function ConvertTo-YuzuCanonicalWindowsPath {
  param([AllowEmptyString()][string]$Path)

  $value = $Path.Trim().Replace('/','\')
  $prefix = ''
  if($value -match '^(?<drive>[A-Za-z]:)(?<rest>\\.*)$'){
    $prefix = $Matches.drive.ToUpperInvariant()
    $segments = @($Matches.rest -split '\\+')
  } elseif($value.StartsWith('\\')){
    $prefix = '\\'
    $segments = @($value.TrimStart([char]'\') -split '\\+')
  } else {
    $segments = @($value -split '\\+')
  }
  $stack = [Collections.Generic.List[string]]::new()
  foreach($segment in $segments){
    if([string]::IsNullOrEmpty($segment) -or $segment -eq '.'){ continue }
    if($segment -eq '..' -and $stack.Count -gt 0 -and $stack[$stack.Count - 1] -ne '..'){
      $stack.RemoveAt($stack.Count - 1)
    } else {
      $stack.Add($segment)
    }
  }
  $body = $stack -join '\'
  if($prefix -eq '\\'){ return ('\\' + $body).ToUpperInvariant() }
  if($prefix){ return ($prefix + '\' + $body).TrimEnd('\').ToUpperInvariant() }
  $body.ToUpperInvariant()
}

function Read-YuzuToolchainContract {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Path
  )

  if(-not (Test-Path -LiteralPath $Path)){
    throw "toolchain contract not found: $Path"
  }
  try {
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "toolchain contract is not valid JSON: $Path ($($_.Exception.Message))"
  }
}

function New-YuzuToolchainManifestDocument {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][psobject]$PriorManifest,
    [Parameter(Mandatory)][psobject]$Contract,
    [Parameter(Mandatory)][string]$HostName,
    [DateTimeOffset]$GeneratedAt = [DateTimeOffset]::UtcNow
  )

  if([string]::IsNullOrWhiteSpace($HostName)){ throw 'manifest host name is required' }
  if(-not [string]::Equals([string]$PriorManifest.host, $HostName, [StringComparison]::OrdinalIgnoreCase)){
    throw "prior manifest host '$($PriorManifest.host ?? '<unset>')' does not match '$HostName'"
  }
  $runnerCount = 0
  if(-not [int]::TryParse([string]$PriorManifest.runner_count, [ref]$runnerCount) -or $runnerCount -lt 1){
    throw "prior manifest runner_count '$($PriorManifest.runner_count ?? '<unset>')' must be a positive integer"
  }
  $databases = @($PriorManifest.telemetry.databases)
  $clusters = @($PriorManifest.postgres_clusters)
  if($databases.Count -ne $runnerCount -or $clusters.Count -ne $runnerCount){
    throw "prior manifest topology does not match runner_count $runnerCount"
  }
  $wantedAgents = @(0..($runnerCount - 1)) -join ','
  $actualAgents = @($clusters | ForEach-Object { [int]$_.agent } | Sort-Object) -join ','
  if($actualAgents -ne $wantedAgents){
    throw "prior manifest PostgreSQL agents '$actualAgents' must be exactly '$wantedAgents'"
  }

  $artifactNames = @($Contract.artifact_probes | ForEach-Object { [string]$_.tool })
  $tools = [Collections.Generic.List[object]]::new()
  foreach($tool in @($PriorManifest.tools)){
    if($artifactNames -notcontains [string]$tool.name){ $tools.Add($tool) }
  }
  foreach($probe in @($Contract.artifact_probes)){
    $pin = [string]$Contract.pins.([string]$probe.pin)
    $tools.Add([pscustomobject][ordered]@{
      name=[string]$probe.tool
      path=([string]$probe.path).Replace('{pin}', $pin)
      version=$pin
      required=$true
    })
  }

  $pins = [ordered]@{}
  foreach($pin in $Contract.pins.PSObject.Properties){ $pins[$pin.Name] = $pin.Value }
  $buildJobs = $null
  $hasBuildJobs = if($PriorManifest.pins -is [Collections.IDictionary]){
    if($PriorManifest.pins.Contains('build_jobs')){
      $buildJobs = $PriorManifest.pins['build_jobs']
      $true
    } else { $false }
  } else {
    $property = $PriorManifest.pins.PSObject.Properties['build_jobs']
    if($null -ne $property){
      $buildJobs = $property.Value
      $true
    } else { $false }
  }
  if($hasBuildJobs){
    $pins.build_jobs = $buildJobs
  }
  $pins.vcpkg_baseline = [string]$Contract.job_pins.vcpkg_baseline

  [pscustomobject][ordered]@{
    schema=[string]$Contract.schema
    generated=$GeneratedAt.ToUniversalTime().ToString('o')
    host=$HostName
    runner_count=$runnerCount
    pins=[pscustomobject]$pins
    env=$PriorManifest.env
    telemetry=$PriorManifest.telemetry
    postgres_clusters=$PriorManifest.postgres_clusters
    tools=[object[]]$tools
  }
}

function Install-YuzuToolchainManifestCandidate {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][psobject]$Candidate,
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][string]$ContractPath,
    [Parameter(Mandatory)][string]$AssertPath,
    [scriptblock]$BeforeReplace
  )

  $directory = Split-Path -Parent $ManifestPath
  New-Item -ItemType Directory -Force -Path $directory | Out-Null
  $leaf = Split-Path -Leaf $ManifestPath
  $candidatePath = Join-Path $directory ".$leaf.$([guid]::NewGuid().ToString('N')).candidate"
  $backupPath = "$ManifestPath.pre-update-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffffffZ')).bak"
  try {
    $Candidate | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $candidatePath -Encoding UTF8
    # Assert-Toolchain is a CLI wrapper and calls `exit`; invoking it with `&`
    # would terminate this updater on success before File.Replace. A child pwsh
    # preserves that CLI contract and turns its exit status into data here.
    $pwsh = (Get-Process -Id $PID).Path
    & $pwsh -NoProfile -File $AssertPath -ManifestPath $candidatePath -ContractPath $ContractPath
    if($LASTEXITCODE -ne 0){ throw "candidate live assertion exited $LASTEXITCODE" }
    if($BeforeReplace){ & $BeforeReplace }
    [IO.File]::Replace($candidatePath, $ManifestPath, $backupPath, $true)
    [pscustomobject]@{ ManifestPath=$ManifestPath; BackupPath=$backupPath }
  } catch {
    if(Test-Path -LiteralPath $candidatePath){ Remove-Item -LiteralPath $candidatePath -Force }
    throw
  }
}

function Invoke-YuzuContractProbe {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Executable,
    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [string[]]$Arguments,
    [ValidateRange(1,30)]
    [int]$TimeoutSeconds = 10
  )

  $process = [Diagnostics.Process]::new()
  try {
    $process.StartInfo = [Diagnostics.ProcessStartInfo]::new()
    $process.StartInfo.FileName = $Executable
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    foreach($argument in $Arguments){ $process.StartInfo.ArgumentList.Add($argument) }
    if(-not $process.Start()){ throw "could not start '$Executable'" }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit($TimeoutSeconds * 1000)){
      try { $process.Kill($true) } catch { $process.Kill() }
      $process.WaitForExit()
      throw "'$Executable' timed out after ${TimeoutSeconds}s"
    }
    $output = (($stdout.GetAwaiter().GetResult(), $stderr.GetAwaiter().GetResult()) |
      Where-Object { -not [string]::IsNullOrEmpty($_) }) -join "`n"
    $exitCode = $process.ExitCode
  } catch {
    throw "could not execute '$Executable': $($_.Exception.Message)"
  } finally {
    $process.Dispose()
  }
  if($exitCode -ne 0){
    throw "'$Executable' exited $exitCode"
  }
  [string]$output
}

function Resolve-YuzuEffectiveCommand {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Name
  )

  # Get-Command returns every PATH match. Invocation uses the first one;
  # string-casting the whole result concatenates all Source values and falsely
  # reports drift whenever a lower-priority duplicate exists.
  $resolved = @(Get-Command -Name $Name -CommandType Application -ErrorAction Stop)
  if($resolved.Count -eq 0){ throw "effective command '$Name' was not found" }
  [string]$resolved[0].Source
}

function Resolve-YuzuPinnedPython {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$ExpectedVersion,
    [Parameter(Mandatory)]
    [scriptblock]$CommandResolver,
    [Parameter(Mandatory)]
    [scriptblock]$VersionProbe,
    [Parameter(Mandatory)]
    [scriptblock]$Installer
  )

  $resolve = {
    $path = [string](& $CommandResolver)
    $version = if([string]::IsNullOrWhiteSpace($path)){
      ''
    } else {
      ([string](& $VersionProbe $path)).Trim()
    }
    [pscustomobject]@{ Path=$path; Version=$version }
  }

  $observed = & $resolve
  $installed = $false
  if(-not [string]::Equals($observed.Version, $ExpectedVersion, [StringComparison]::OrdinalIgnoreCase)){
    & $Installer | Out-Host
    $installed = $true
    $observed = & $resolve
  }
  if(-not [string]::Equals($observed.Version, $ExpectedVersion, [StringComparison]::OrdinalIgnoreCase)){
    throw "python is '$($observed.Version ?? '<missing>')'; reviewed pin is '$ExpectedVersion'"
  }

  [pscustomobject]@{
    Path = [string]$observed.Path
    Version = [string]$observed.Version
    Installed = $installed
  }
}

function Get-YuzuInstallerDisposition {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [int]$ExitCode
  )

  switch($ExitCode){
    0 { 'Complete'; break }
    1641 { 'RebootRequired'; break }
    3010 { 'RebootRequired'; break }
    -1978334967 { 'RebootRequired'; break } # WinGet: reboot required to finish
    -1978334966 { 'RebootRequired'; break } # WinGet: reboot required before install
    -1978334965 { 'RebootRequired'; break } # WinGet: reboot initiated
    default { 'Failed' }
  }
}

function Invoke-YuzuInstallerExitPolicy {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [int]$ExitCode,
    [Parameter(Mandatory)]
    [string]$Context,
    [Parameter(Mandatory)]
    [scriptblock]$RebootHandler
  )

  $disposition = Get-YuzuInstallerDisposition -ExitCode $ExitCode
  if($disposition -eq 'Complete'){ return }
  if($disposition -eq 'RebootRequired'){
    & $RebootHandler $Context $ExitCode
    throw "$Context requires a reboot, but its reboot handler returned"
  }
  throw "$Context failed (exit $ExitCode)"
}

function Test-YuzuRequiredToolPaths {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [object[]]$Tools,
    [scriptblock]$PathTester
  )

  if(-not $PathTester){
    $PathTester = { param([string]$path) Test-Path -LiteralPath $path }
  }
  $observations = foreach($tool in $Tools){
    $exists = $false
    $pathError = ''
    if(-not [string]::IsNullOrWhiteSpace([string]$tool.path)){
      try { $exists = [bool](& $PathTester ([string]$tool.path)) }
      catch { $exists = $false; $pathError = $_.Exception.Message }
    }
    [pscustomobject]@{
      Name = [string]$tool.name
      Path = [string]$tool.path
      Version = [string]$tool.version
      Required = ($tool.required -eq $true)
      Exists = $exists
      Error = $pathError
    }
  }
  [pscustomobject]@{
    Healthy = @($observations | Where-Object { $_.Required -and -not $_.Exists }).Count -eq 0
    Observations = [object[]]$observations
  }
}

function Test-YuzuToolchainManifest {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [psobject]$Manifest,
    [Parameter(Mandatory)]
    [psobject]$Contract,
    [scriptblock]$ProbeRunner,
    [scriptblock]$CommandResolver,
    [scriptblock]$FileProbeReader,
    [string]$ExpectedHost
  )

  $errors = [Collections.Generic.List[string]]::new()
  $observations = [Collections.Generic.List[object]]::new()

  $probeTimeout = 0
  if(-not [int]::TryParse([string]$Contract.probe_timeout_seconds, [ref]$probeTimeout) -or
     $probeTimeout -lt 1 -or $probeTimeout -gt 30){
    $errors.Add("contract probe_timeout_seconds '$($Contract.probe_timeout_seconds ?? '<unset>')' must be in 1..30")
  }

  if(-not $ProbeRunner){
    # A closure created with GetNewClosure executes in its own dynamic module;
    # capture the private implementation as a scriptblock so the exported
    # contract functions do not lose it when invoked from a caller's scope.
    $probeImplementation = ${function:Invoke-YuzuContractProbe}
    $ProbeRunner = { param([string]$executable,[string[]]$arguments)
      & $probeImplementation -Executable $executable -Arguments $arguments -TimeoutSeconds $probeTimeout
    }.GetNewClosure()
  }
  if(-not $CommandResolver){
    $resolverImplementation = ${function:Resolve-YuzuEffectiveCommand}
    $CommandResolver = { param([string]$command)
      & $resolverImplementation -Name $command
    }.GetNewClosure()
  }
  if(-not $FileProbeReader){
    $FileProbeReader = { param([string]$anchorPath,[psobject]$probe)
      $root = $anchorPath
      for($n=0; $n -lt [int]$probe.root_ascend; $n++){
        $root = Split-Path -Path $root -Parent
      }
      $matches = @(Get-ChildItem -Path (Join-Path $root ([string]$probe.path_glob)) -File -ErrorAction Stop)
      if($matches.Count -ne 1){
        throw "file probe '$($probe.name)' found $($matches.Count) matches under $root"
      }
      Get-Content -LiteralPath $matches[0].FullName -Raw -ErrorAction Stop
    }
  }

  $contractSchema = [string]$Contract.schema
  $contractSchemaDisplay = if([string]::IsNullOrWhiteSpace($contractSchema)){ '<unset>' } else { $contractSchema }
  if($contractSchema -ne $script:SupportedSchema){
    $errors.Add("contract schema '$contractSchemaDisplay' is unsupported; expected $script:SupportedSchema")
  }

  $requireUnique = {
    param([string]$label,[string[]]$actual,[string[]]$required)
    foreach($name in $required){
      $count = @($actual | Where-Object { $_ -eq $name }).Count
      if($count -ne 1){ $errors.Add("contract must contain exactly one $label '$name'; found $count") }
    }
    foreach($group in @($actual | Group-Object)){
      if($group.Count -gt 1){ $errors.Add("contract has duplicate $label '$($group.Name)'") }
    }
    foreach($name in $actual){
      if($required -notcontains $name){ $errors.Add("contract has unsupported $label '$name' for $script:SupportedSchema") }
    }
  }
  $contractPins = @($Contract.pins.PSObject.Properties | ForEach-Object Name)
  $contractAcceptedPins = @($Contract.accepted_host_pins.PSObject.Properties | ForEach-Object Name)
  $contractJobPins = @($Contract.job_pins.PSObject.Properties | ForEach-Object Name)
  $contractEnv = @($Contract.required_env | ForEach-Object { [string]$_ })
  $contractTools = @($Contract.required_tools | ForEach-Object { [string]$_ })
  $artifactProbeNames = @($Contract.artifact_probes | ForEach-Object { [string]$_.tool })
  $effectiveCommands = @($Contract.effective_commands | ForEach-Object { [string]$_.command })
  $toolProbeNames = @($Contract.tool_probes | ForEach-Object { [string]$_.tool })
  $fileProbeNames = @($Contract.file_probes | ForEach-Object { [string]$_.name })
  & $requireUnique 'pin' $contractPins $script:V1Pins
  & $requireUnique 'accepted host pin' $contractAcceptedPins $script:V1Pins
  & $requireUnique 'job pin' $contractJobPins $script:V1JobPins
  & $requireUnique 'required env' $contractEnv $script:V1Environment
  & $requireUnique 'required tool' $contractTools $script:V1Tools
  & $requireUnique 'artifact probe' $artifactProbeNames $script:V1ArtifactProbes
  & $requireUnique 'effective command' $effectiveCommands $script:V1EffectiveCommands
  & $requireUnique 'tool probe' $toolProbeNames $script:V1ToolProbes
  & $requireUnique 'file probe' $fileProbeNames $script:V1FileProbes

  foreach($name in $script:V1Pins){
    $accepted = @($Contract.accepted_host_pins.$name | ForEach-Object { [string]$_ })
    if($accepted.Count -eq 0 -or @($accepted | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count){
      $errors.Add("contract accepted host pin '$name' must contain at least one nonempty version")
      continue
    }
    if(@($accepted | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique).Count -ne $accepted.Count){
      $errors.Add("contract accepted host pin '$name' contains duplicate versions")
    }
    if($accepted -notcontains [string]$Contract.pins.$name){
      $errors.Add("contract target pin '$name' must appear in accepted_host_pins")
    }
  }

  foreach($mapping in @($Contract.effective_commands)){
    if($contractTools -notcontains [string]$mapping.tool){
      $errors.Add("effective command '$($mapping.command)' references unknown tool '$($mapping.tool)'")
    }
  }
  foreach($probe in @($Contract.artifact_probes)){
    if($contractTools -notcontains [string]$probe.tool -or $contractPins -notcontains [string]$probe.pin){
      $errors.Add("artifact probe '$($probe.tool)' references an unknown tool or pin")
    }
    if([string]::IsNullOrWhiteSpace([string]$probe.path) -or
       -not ([string]$probe.path).Contains('{pin}')){
      $errors.Add("artifact probe '$($probe.tool)' must have a path containing {pin}")
    }
  }
  foreach($probe in @($Contract.tool_probes)){
    $launcher = if($probe.PSObject.Properties['executable_tool']){ [string]$probe.executable_tool } else { [string]$probe.tool }
    if($contractTools -notcontains [string]$probe.tool -or $contractTools -notcontains $launcher){
      $errors.Add("tool probe '$($probe.tool)' references an unknown tool or launcher")
    }
    $hasPin = $probe.PSObject.Properties['pin'] -and -not [string]::IsNullOrWhiteSpace([string]$probe.pin)
    $usesRecorded = [string]$probe.compare_to -eq 'recorded_version'
    if($hasPin -eq $usesRecorded){
      $errors.Add("tool probe '$($probe.tool)' must select exactly one of pin or compare_to=recorded_version")
    } elseif($hasPin -and $contractPins -notcontains [string]$probe.pin){
      $errors.Add("tool probe '$($probe.tool)' references unknown pin '$($probe.pin)'")
    }
    try {
      $regex = [regex]::new([string]$probe.version_regex)
      if($regex.GetGroupNames() -notcontains 'version'){ throw 'missing named version group' }
    } catch {
      $errors.Add("tool probe '$($probe.tool)' has invalid version_regex ($($_.Exception.Message))")
    }
  }
  foreach($probe in @($Contract.file_probes)){
    if($contractTools -notcontains [string]$probe.anchor_tool -or $contractPins -notcontains [string]$probe.pin){
      $errors.Add("file probe '$($probe.name)' references an unknown tool or pin")
    }
    if([int]$probe.root_ascend -lt 1 -or [string]::IsNullOrWhiteSpace([string]$probe.path_glob)){
      $errors.Add("file probe '$($probe.name)' has an invalid path adapter")
    }
  }
  $manifestSchema = [string]$Manifest.schema
  $manifestSchemaDisplay = if([string]::IsNullOrWhiteSpace($manifestSchema)){ '<unset>' } else { $manifestSchema }
  if($manifestSchema -ne $contractSchema){
    $errors.Add("manifest schema '$manifestSchemaDisplay' is incompatible with contract schema '$contractSchemaDisplay'; re-run provisioning")
  }

  if([string]::IsNullOrWhiteSpace([string]$Manifest.host)){
    $errors.Add('manifest host is missing')
  } elseif(-not [string]::IsNullOrWhiteSpace($ExpectedHost) -and
           -not [string]::Equals([string]$Manifest.host, $ExpectedHost, [StringComparison]::OrdinalIgnoreCase)){
    $errors.Add("manifest host '$($Manifest.host)' does not match this computer '$ExpectedHost'")
  }
  $generatedValue = $Manifest.generated
  $generated = [DateTimeOffset]::MinValue
  # PowerShell 7.5+ ConvertFrom-Json materialises ISO-8601 strings as DateTime.
  # Casting that value back to string is culture-sensitive (for example,
  # 14 August becomes 08/14 under en-US and then fails under en-GB).
  $generatedIsValid = $generatedValue -is [DateTime] -or
                      $generatedValue -is [DateTimeOffset] -or
                      [DateTimeOffset]::TryParse([string]$generatedValue, [ref]$generated)
  if(-not $generatedIsValid){
    $errors.Add("manifest generated timestamp '$($Manifest.generated ?? '<unset>')' is invalid")
  }

  $runnerCount = 0
  if(-not [int]::TryParse([string]$Manifest.runner_count, [ref]$runnerCount) -or $runnerCount -lt 1){
    $errors.Add("manifest runner_count '$($Manifest.runner_count ?? '<unset>')' must be a positive integer")
  }

  if(-not $Contract.pins){
    $errors.Add('contract pins are missing')
  } elseif(-not $Manifest.pins){
    $errors.Add('manifest pins are missing')
  } else {
    foreach($pin in $Contract.pins.PSObject.Properties){
      $actualProperty = $Manifest.pins.PSObject.Properties[$pin.Name]
      $actual = if($actualProperty){ [string]$actualProperty.Value } else { $null }
      $accepted = @($Contract.accepted_host_pins.($pin.Name) | ForEach-Object { [string]$_ })
      $matched = @($accepted | Where-Object { [string]::Equals($actual, $_, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 1
      if(-not $actualProperty -or -not $matched){
        $errors.Add("manifest pin '$($pin.Name)' is '$($actual ?? '<unset>')'; accepted: '$($accepted -join "', '")'")
      }
    }
  }

  if(-not $Manifest.env){
    $errors.Add('manifest env contract is missing')
  } else {
    foreach($name in @($Contract.required_env)){
      $property = $Manifest.env.PSObject.Properties[[string]$name]
      if(-not $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)){
        $errors.Add("manifest env '$name' is missing or empty")
      }
    }
  }

  $manifestTools = @($Manifest.tools)
  foreach($name in @($Contract.required_tools)){
    $matches = @($manifestTools | Where-Object { [string]$_.name -eq [string]$name })
    if($matches.Count -ne 1){
      $errors.Add("manifest must contain exactly one '$name' tool; found $($matches.Count)")
      continue
    }
    if($matches[0].required -ne $true){
      $errors.Add("manifest tool '$name' must be required")
    }
    if([string]::IsNullOrWhiteSpace([string]$matches[0].path)){
      $errors.Add("manifest tool '$name' has no path")
    }
  }

  foreach($probe in @($Contract.artifact_probes)){
    $matches = @($manifestTools | Where-Object { [string]$_.name -eq [string]$probe.tool })
    if($matches.Count -ne 1){ continue }
    $tool = $matches[0]
    $expectedVersion = [string]$Manifest.pins.([string]$probe.pin)
    if(-not [string]::Equals([string]$tool.version, $expectedVersion, [StringComparison]::OrdinalIgnoreCase)){
      $errors.Add("manifest tool '$($probe.tool)' version is '$($tool.version ?? '<unset>')'; expected '$expectedVersion'")
    }
    $expectedPath = ([string]$probe.path).Replace('{pin}', $expectedVersion)
    $actualPath = ConvertTo-YuzuCanonicalWindowsPath ([string]$tool.path)
    $canonicalExpected = ConvertTo-YuzuCanonicalWindowsPath $expectedPath
    $matched = [string]::Equals($actualPath, $canonicalExpected, [StringComparison]::OrdinalIgnoreCase)
    $observations.Add([pscustomobject]@{ Name=[string]$probe.tool; Actual=[string]$tool.path; Expected=$expectedPath; Matched=$matched })
    if(-not $matched){
      $errors.Add("manifest tool '$($probe.tool)' path '$($tool.path)' does not equal '$expectedPath'")
    }
  }

  $databases = @($Manifest.telemetry.databases)
  if(-not $Manifest.telemetry -or $databases.Count -ne $runnerCount){
    $errors.Add("manifest telemetry databases count $($databases.Count) does not match runner_count $runnerCount")
  } elseif(@($databases | Where-Object { [string]::IsNullOrWhiteSpace([string]$_) }).Count){
    $errors.Add('manifest telemetry contains an empty database path')
  } elseif(@($databases | ForEach-Object { ConvertTo-YuzuCanonicalWindowsPath ([string]$_) } | Select-Object -Unique).Count -ne $databases.Count){
    $errors.Add('manifest telemetry database paths must be unique per runner')
  }
  $clusters = @($Manifest.postgres_clusters)
  if($clusters.Count -ne $runnerCount){
    $errors.Add("manifest PostgreSQL cluster count $($clusters.Count) does not match runner_count $runnerCount")
  } elseif($runnerCount -gt 0) {
    $agentIds = @()
    $ports = @()
    foreach($cluster in $clusters){
      $agent = -1
      if(-not [int]::TryParse([string]$cluster.agent, [ref]$agent)){
        $errors.Add("manifest PostgreSQL cluster agent '$($cluster.agent ?? '<unset>')' is invalid")
      } else {
        $agentIds += $agent
      }
      $port = 0
      if(-not [int]::TryParse([string]$cluster.port, [ref]$port) -or $port -lt 1 -or $port -gt 65535){
        $errors.Add("manifest PostgreSQL cluster agent $agent has invalid port '$($cluster.port ?? '<unset>')'")
      } else {
        $ports += $port
      }
      foreach($field in @('service','bin','pg_ctl','postgres','psql','pg_isready')){
        if([string]::IsNullOrWhiteSpace([string]$cluster.$field)){
          $errors.Add("manifest PostgreSQL cluster agent $agent has no $field")
        }
      }
    }
    $wantedAgents = @(0..($runnerCount - 1))
    if((@($agentIds | Sort-Object) -join ',') -ne ($wantedAgents -join ',')){
      $errors.Add("manifest PostgreSQL agents '$(@($agentIds | Sort-Object) -join ',')' must be exactly '$($wantedAgents -join ',')'")
    }
    if(@($ports | Select-Object -Unique).Count -ne $ports.Count){
      $errors.Add('manifest PostgreSQL port values must be unique per runner')
    }
    foreach($field in @('service','bin','pg_ctl','postgres','psql','pg_isready')){
      $values = if($field -eq 'service'){
        @($clusters | ForEach-Object { ([string]$_.$field).ToUpperInvariant() })
      } else {
        @($clusters | ForEach-Object { ConvertTo-YuzuCanonicalWindowsPath ([string]$_.$field) })
      }
      if(@($values | Select-Object -Unique).Count -ne $values.Count){
        $errors.Add("manifest PostgreSQL $field values must be unique per runner")
      }
    }
  }

  # Malformed/incompatible data is never executable. This is a correctness
  # boundary, not a security boundary: current Windows runners execute jobs as
  # LOCAL SYSTEM, so runner privilege isolation must be fixed separately.
  if($errors.Count -eq 0){
    foreach($mapping in @($Contract.effective_commands)){
      $tool = @($manifestTools | Where-Object { [string]$_.name -eq [string]$mapping.tool })[0]
      try {
        $effective = & $CommandResolver ([string]$mapping.command)
        $matched = [string]::Equals(([string]$effective).TrimEnd('\','/'), ([string]$tool.path).TrimEnd('\','/'), [StringComparison]::OrdinalIgnoreCase)
        $observations.Add([pscustomobject]@{ Name="$($mapping.command) command"; Actual=[string]$effective; Expected=[string]$tool.path; Matched=$matched })
        if(-not $matched){
          $errors.Add("effective command '$($mapping.command)' resolves to '$effective'; manifest records '$($tool.path)'")
        }
      } catch {
        $errors.Add("effective command '$($mapping.command)' could not be resolved: $($_.Exception.Message)")
      }
    }

    foreach($probe in @($Contract.tool_probes)){
      $tool = @($manifestTools | Where-Object { [string]$_.name -eq [string]$probe.tool })[0]
      $executableToolName = if($probe.PSObject.Properties['executable_tool']){
        [string]$probe.executable_tool
      } else {
        [string]$probe.tool
      }
      $executableTool = @($manifestTools | Where-Object { [string]$_.name -eq $executableToolName })[0]
      $arguments = @($probe.arguments | ForEach-Object {
        ([string]$_).Replace('{tool_path}', [string]$tool.path)
      })
      $expected = if([string]$probe.compare_to -eq 'recorded_version'){
        [string]$tool.version
      } else {
        [string]$Manifest.pins.([string]$probe.pin)
      }
      try {
        $output = & $ProbeRunner ([string]$executableTool.path) ([string[]]$arguments)
        $match = [regex]::Match([string]$output, [string]$probe.version_regex)
        if(-not $match.Success -or -not $match.Groups['version'].Success){
          $errors.Add("$($probe.tool) version probe returned an unrecognized value: $([string]$output)")
          continue
        }
        $actual = $match.Groups['version'].Value
        $matched = [string]::Equals($actual, $expected, [StringComparison]::OrdinalIgnoreCase)
        $observations.Add([pscustomobject]@{ Name=[string]$probe.tool; Actual=$actual; Expected=$expected; Matched=$matched })
        if(-not $matched){
          $errors.Add("$($probe.tool) version is '$actual'; expected '$expected'")
        }
      } catch {
        $errors.Add("$($probe.tool) version probe failed: $($_.Exception.Message)")
      }
    }

    foreach($probe in @($Contract.file_probes)){
      $anchor = @($manifestTools | Where-Object { [string]$_.name -eq [string]$probe.anchor_tool })[0]
      $expected = [string]$Manifest.pins.([string]$probe.pin)
      try {
        $output = & $FileProbeReader ([string]$anchor.path) $probe
        $match = [regex]::Match([string]$output, [string]$probe.version_regex)
        if(-not $match.Success -or -not $match.Groups['version'].Success){
          $errors.Add("$($probe.name) file probe returned an unrecognized value: $([string]$output)")
          continue
        }
        $actual = $match.Groups['version'].Value
        $matched = [string]::Equals($actual, $expected, [StringComparison]::OrdinalIgnoreCase)
        $observations.Add([pscustomobject]@{ Name=[string]$probe.name; Actual=$actual; Expected=$expected; Matched=$matched })
        if(-not $matched){
          $errors.Add("$($probe.name) is '$actual'; expected '$expected'")
        }
      } catch {
        $errors.Add("$($probe.name) file probe failed: $($_.Exception.Message)")
      }
    }

  }

  [pscustomobject]@{
    Healthy = ($errors.Count -eq 0)
    Schema = $manifestSchema
    Errors = [string[]]$errors
    Observations = [object[]]$observations
  }
}

function Test-YuzuVcpkgCheckout {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [psobject]$Contract,
    [Parameter(Mandatory)]
    [string]$VcpkgRoot,
    [scriptblock]$ProbeRunner,
    [scriptblock]$MetadataReader,
    [string]$GitExecutable = 'git'
  )

  $errors = [Collections.Generic.List[string]]::new()
  $observations = [Collections.Generic.List[object]]::new()
  $probeTimeout = 0
  if(-not [int]::TryParse([string]$Contract.probe_timeout_seconds, [ref]$probeTimeout) -or
     $probeTimeout -lt 1 -or $probeTimeout -gt 30){
    $errors.Add("contract probe_timeout_seconds '$($Contract.probe_timeout_seconds ?? '<unset>')' must be in 1..30")
  }
  if([string]$Contract.schema -ne $script:SupportedSchema){
    $errors.Add("contract schema '$($Contract.schema ?? '<unset>')' is unsupported; expected $script:SupportedSchema")
  }
  $jobPinNames = @($Contract.job_pins.PSObject.Properties | ForEach-Object Name)
  foreach($required in $script:V1JobPins){
    if(@($jobPinNames | Where-Object { $_ -eq $required }).Count -ne 1){
      $errors.Add("contract must contain exactly one job pin '$required'")
    }
  }
  foreach($name in $jobPinNames){
    if($script:V1JobPins -notcontains $name){
      $errors.Add("contract has unsupported job pin '$name' for $script:SupportedSchema")
    }
  }
  $expected = [string]$Contract.job_pins.vcpkg_baseline
  if($expected -notmatch '^[0-9a-fA-F]{40}$'){
    $errors.Add("contract vcpkg_baseline '$($expected ?? '<unset>')' is not a 40-character commit SHA")
  }
  if([string]::IsNullOrWhiteSpace($VcpkgRoot)){
    $errors.Add('vcpkg checkout root is empty')
  }
  if(-not $ProbeRunner){
    $probeImplementation = ${function:Invoke-YuzuContractProbe}
    $ProbeRunner = { param([string]$executable,[string[]]$arguments)
      & $probeImplementation -Executable $executable -Arguments $arguments -TimeoutSeconds $probeTimeout
    }.GetNewClosure()
  }
  if(-not $MetadataReader){
    $MetadataReader = { param([string]$root)
      Get-Content -LiteralPath (Join-Path $root 'scripts\vcpkg-tool-metadata.txt') -Raw -ErrorAction Stop
    }
  }

  if($errors.Count -eq 0){
    try {
      $actual = ([string](& $ProbeRunner $GitExecutable ([string[]]@('-C',$VcpkgRoot,'rev-parse','HEAD')))).Trim()
      $matched = [string]::Equals($actual, $expected, [StringComparison]::OrdinalIgnoreCase)
      $observations.Add([pscustomobject]@{ Name='vcpkg checkout HEAD'; Actual=$actual; Expected=$expected; Matched=$matched })
      if(-not $matched){ $errors.Add("vcpkg checkout HEAD is '$actual'; expected '$expected'") }
    } catch {
      $errors.Add("vcpkg checkout HEAD probe failed: $($_.Exception.Message)")
    }
    try {
      $actual = ([string](& $ProbeRunner $GitExecutable ([string[]]@('-C',$VcpkgRoot,'status','--porcelain','--untracked-files=no')))).Trim()
      $matched = [string]::IsNullOrEmpty($actual)
      $shown = if($matched){ '<clean>' } else { $actual }
      $observations.Add([pscustomobject]@{ Name='vcpkg tracked tree'; Actual=$shown; Expected='<clean>'; Matched=$matched })
      if(-not $matched){ $errors.Add("vcpkg tracked tree is '$shown'; expected '<clean>'") }
    } catch {
      $errors.Add("vcpkg tracked-tree probe failed: $($_.Exception.Message)")
    }
    try {
      $metadata = [string](& $MetadataReader $VcpkgRoot)
      $metadataMatch = [regex]::Match($metadata, '(?m)^VCPKG_TOOL_RELEASE_TAG=(?<release>[^\r\n]+)\s*$')
      if(-not $metadataMatch.Success){
        throw 'scripts/vcpkg-tool-metadata.txt has no VCPKG_TOOL_RELEASE_TAG'
      }
      $expectedRelease = $metadataMatch.Groups['release'].Value.Trim()
      $vcpkgExecutable = Join-Path $VcpkgRoot 'vcpkg.exe'
      $output = [string](& $ProbeRunner $vcpkgExecutable ([string[]]@('version')))
      $match = [regex]::Match($output, '(?im)^vcpkg package management program version (?<version>\S+)\s*$')
      if(-not $match.Success){
        $errors.Add("effective vcpkg version probe returned an unrecognized value: $output")
      } else {
        $actual = $match.Groups['version'].Value
        $matched = [string]::Equals($actual, $expectedRelease, [StringComparison]::OrdinalIgnoreCase) -or
          $actual.StartsWith("$expectedRelease-", [StringComparison]::OrdinalIgnoreCase)
        $observations.Add([pscustomobject]@{ Name='effective vcpkg tool release'; Actual=$actual; Expected="$expectedRelease-*"; Matched=$matched })
        if(-not $matched){ $errors.Add("effective vcpkg executable reports '$actual'; checkout metadata requires release '$expectedRelease'") }
      }
    } catch {
      $errors.Add("effective vcpkg executable probe failed: $($_.Exception.Message)")
    }
  }

  [pscustomobject]@{
    Healthy = ($errors.Count -eq 0)
    Errors = [string[]]$errors
    Observations = [object[]]$observations
  }
}

Export-ModuleMember -Function Get-YuzuInstallerDisposition,Install-YuzuToolchainManifestCandidate,Invoke-YuzuContractProbe,Invoke-YuzuInstallerExitPolicy,New-YuzuToolchainManifestDocument,Read-YuzuToolchainContract,Resolve-YuzuEffectiveCommand,Resolve-YuzuPinnedPython,Test-YuzuRequiredToolPaths,Test-YuzuToolchainManifest,Test-YuzuVcpkgCheckout
