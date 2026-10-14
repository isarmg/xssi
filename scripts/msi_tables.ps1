param([Parameter(Mandatory=$true)][string]$Artifact,[Parameter(Mandatory=$true)][string]$Output)
$env:PSModulePath=[Environment]::GetEnvironmentVariable('PSModulePath','Machine')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$installer=New-Object -ComObject WindowsInstaller.Installer
$database=$installer.OpenDatabase((Resolve-Path -LiteralPath $Artifact).Path,0)
function Read-Table([string]$Query,[int]$Columns) {
    $view=$database.OpenView($Query)
    [void]$view.Execute()
    $values=[Collections.Generic.List[object]]::new()
    try {
        while (($record=$view.Fetch()) -ne $null) {
            if ($values.Count -ge 100000) {throw 'MSI table exceeds the reviewed row bound.'}
            $row=[Collections.Generic.List[string]]::new()
            for ($index=1;$index -le $Columns;$index++) {
                $value=[string]$record.StringData($index)
                if ($value.Length -gt 65536) {throw 'MSI table value exceeds the reviewed field bound.'}
                [void]$row.Add($value)
            }
            [void]$values.Add([object]$row.ToArray())
        }
    } finally {[void]$view.Close()}
    # A scalar envelope keeps empty/single-column rows out of PowerShell's
    # pipeline enumeration and prevents COM method return values becoming rows.
    return [pscustomobject]@{rows=$values.ToArray()}
}
$tableRows=Read-Table 'SELECT `Name` FROM `_Tables`' 1
$tableNames=@($tableRows.rows|ForEach-Object {$_[0]})
function Read-OptionalTable([string]$Name,[string]$Query,[int]$Columns) {
    if ($tableNames -contains $Name) {return (Read-Table $Query $Columns)}
    return [pscustomobject]@{rows=@()}
}
$otherSequences=[Collections.Generic.List[object]]::new()
foreach ($name in @('AdminExecuteSequence','AdminUISequence','AdvtExecuteSequence','InstallUISequence')) {
    foreach ($row in (Read-OptionalTable $name ('SELECT `Action`, `Condition`, `Sequence` FROM `'+$name+'`') 3).rows) {
        $otherSequences.Add(@($name,$row[0],$row[1],$row[2]))
    }
}
$summary=$database.SummaryInformation(0)
$result=@{
    table_names=$tableNames
    properties=(Read-Table 'SELECT `Property`, `Value` FROM `Property`' 2).rows
    actions=(Read-OptionalTable 'CustomAction' 'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`' 4).rows
    sequence=(Read-Table 'SELECT `Action`, `Condition`, `Sequence` FROM `InstallExecuteSequence`' 3).rows
    other_sequences=$otherSequences.ToArray()
    services=(Read-OptionalTable 'ServiceInstall' 'SELECT `ServiceInstall`, `Name`, `DisplayName`, `ServiceType`, `StartType`, `ErrorControl`, `LoadOrderGroup`, `Dependencies`, `StartName`, `Password`, `Arguments`, `Component_`, `Description` FROM `ServiceInstall`' 13).rows
    service_controls=(Read-OptionalTable 'ServiceControl' 'SELECT `ServiceControl`, `Name`, `Event`, `Arguments`, `Wait`, `Component_` FROM `ServiceControl`' 6).rows
    registry=(Read-OptionalTable 'Registry' 'SELECT `Registry`, `Root`, `Key`, `Name`, `Value`, `Component_` FROM `Registry`' 6).rows
    environment=(Read-OptionalTable 'Environment' 'SELECT `Environment`, `Name`, `Value`, `Component_` FROM `Environment`' 4).rows
    remove_files=(Read-OptionalTable 'RemoveFile' 'SELECT `FileKey`, `Component_`, `FileName`, `DirProperty`, `InstallMode` FROM `RemoveFile`' 5).rows
    service_config=(Read-OptionalTable 'Wix4ServiceConfig' 'SELECT `ServiceName`, `Component_`, `NewService`, `FirstFailureActionType`, `SecondFailureActionType`, `ThirdFailureActionType`, `ResetPeriodInDays`, `RestartServiceDelayInSeconds`, `ProgramCommandLine`, `RebootMessage` FROM `Wix4ServiceConfig`' 10).rows
    components=(Read-Table 'SELECT `Component`, `ComponentId`, `Directory_`, `Attributes`, `Condition`, `KeyPath` FROM `Component`' 6).rows
    directories=(Read-Table 'SELECT `Directory`, `Directory_Parent`, `DefaultDir` FROM `Directory`' 3).rows
    template=[string]$summary.Property(7)
    installer_version=[int]$summary.Property(14)
}
$json=$result|ConvertTo-Json -Depth 8
if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 4194304) {throw 'MSI policy evidence exceeds its reviewed bound.'}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($Output),$json,[Text.UTF8Encoding]::new($false))
