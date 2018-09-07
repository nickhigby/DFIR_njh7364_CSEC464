$ErrorActionPreference = 'SilentlyContinue'

#Written by Nick Higby

#Time data
function Get-Time {
  $Time = @{}
  $CurrentTime = Get-Date
  $TimeZone = Get-Timezone
  $Uptime = ((get-date) - (gcim Win32_OperatingSystem).LastBootUptime).ToString('g')
  $Time.Uptime = $Uptime
  $Time.CurrentTime = $CurrentTime.ToShortTimeString()
  $Time.TimeZone = $TimeZone.StandardName
  Write-Output ""
  Write-Output "Time:"
  $Time | Format-Table
  $Time | Export-Csv -Path "data.csv"
}

#OS data
function Get-OS {
  $OS = @{}
  $Numerical = [System.Environment]::OSVersion.Version
  $Typical = (Get-WmiObject -class Win32_OperatingSystem).Caption
  $OS.Numerical = $Numerical
  $OS.Typical = $Typical
  Write-Output "OS Version:"
  $OS | Format-Table
  $OS | Export-Csv -Path "data.csv"
}

#Hardware data
function Get-Hardware {
  $Hardware = @{}
  $CPU = (Get-WmiObject -class Win32_Processor).Name
  $RAM = (Get-WMIObject -class Win32_PhysicalMemory |
Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)})
  $DriveName = (Get-WmiObject Win32_LogicalDisk).DeviceID
  $DriveSize = (Get-WmiObject Win32_LogicalDisk).Size | ForEach-Object -Process {[Math]::Round(($_/ 1GB),2)}
  $Hardware.CPU = $CPU
  $Hardware.RAM = $RAM
  $Hardware.DriveID = $DriveName
  $Hardware.Size = $DriveSize
  Write-Output "Hardware:"
  $Hardware | Format-Table
  $Hardware | Export-Csv -Path "data.csv"
}

#Domain Controller data
function Get-DC {
  $DC = @{}
  $HostName = Get-ADDomainController
  $DNS = Get-DnsServer
  $DC.Host = $HostName.HostName
  $DC.IP = $IP.Ipv4address
  $DC.DNS = $DNS
  Write-Output "Domain Controller:"
  $DC | Format-Table
  $DC | Export-Csv -Path "data.csv"
}

#Host and Domain data
function Get-HostAndDomain {
  $HaD = @{}
  $HostName = (Get-WmiObject win32_computersystem).DNSHostName
  $DomainName = (Get-WmiObject win32_computersystem).Domain
  $HaD.HostName = $HostName
  $HaD.DomainName = $DomainName
  Write-Output "Host and Domain Names:"
  $HaD | Format-Table
  $HaD | Export-Csv -Path "data.csv"
}

#User data
function Get-Users {
  $Users = @{}
  $Local = Get-LocalUser
  $Users.LocalName = $Local.Name
  $Users.LocalSID = (($Local).SID).Value
  $Users.LocalAccountCreation = $Local.WhenCreated
  $Users.LocalLastLogon = $Local.LastLogon

  $Domain = Get-ADUser filter=*
  $Users.DomainName = $Domain.Name
  $Users.DomainSID = (($Domain).SID).Value
  $Users.DomainAccountCreation = $Domain.WhenCreated
  $Users.DomainLastLogon = $Domain.LastLogon

  $Service = (Get-WmiObject win32_service).StartName
  $Users.ServiceNames = $Service | select -uniq
  Write-Output "Users:"
  $Users | Format-Table
  $Users | Export-Csv -Path "data.csv"

  Write-Output "Login History:"
  Get-EventLog security | Where-Object {($_.InstanceID -eq 4634) -or ($_.InstanceID -eq 4624)} | Select-Object Index,TimeGenerated,InstanceID,Message
  Get-EventLog security | Where-Object {($_.InstanceID -eq 4634) -or ($_.InstanceID -eq 4624)} | Select-Object Index,TimeGenerated,InstanceID,Message | Export-Csv -Path "data.csv"
}

#Boot data
function Get-Boot {
  $Boot = @{}
  $BootServices = Get-WmiObject Win32_Service | Where-Object {$_.StartMode -eq 'Auto'}
  $BootPrograms = Get-CimInstance Win32_StartupCommand
  $Boot.ProgramName = $BootPrograms.Name
  $Boot.ProgramLocation = $BootPrograms.Location
  $Boot.ProgramCommand = $BootPrograms.Command
  $Boot.ProgramUser = $BootPrograms.User
  $Boot.ServiceName = $BootServices.Name
  Write-Output ""
  Write-Output "Boot:"
  $Boot | Format-Table
  $Boot | Export-Csv -Path "data.csv"
}

#Task data
function Get-Task {
  $Task = @{}
  $TaskName = (Get-ScheduledTask).TaskName
  $Task.TaskName = $TaskName
  Write-Output "Tasks:"
  $Task | Format-Table
  $Task | Export-Csv -Path "data.csv"
}

#Network data
function Get-Network {
  $Network = @{}
  $ARP = Get-NetNeighbor
  $Network.ARPIPAddress = $ARP.IPAddress
  $Network.ARPLinkLayerAddress = $ARP.LinkLayerAddress
  $Network.ARPState = $ARP.State

  $Interfaces = Get-NetAdapter
  $Network.InterfaceName = $Interfaces.Name
  $Network.InterfaceMAC = $Interfaces.MacAddress

  $Routing = Get-NetRoute
  $Network.RoutingDestination = $Routing.DestinationPrefix
  $Network.RoutingNextHop     = $Routing.NextHop
  $Network.RoutingRouteMetric = $Routing.RouteMetric

  $Listening = (Get-NetTCPConnection | Where-Object {($_.State -eq "Listen")})
  $Network.ListeningLocalAddr = $Listening.LocalAddress
  $Network.ListeningLocalPort = $Listening.LocalPort
  $Network.ListeningRemoteAddr= $Listening.RemoteAddress
  $Network.ListeningRemotePort= $Listening.RemotePort
  $Network.ListeningOwningProc= $Listening.OwningProcess

  $Existing = (Get-NetTCPConnection | Where-Object {($_.State -eq "Established")})
  $Network.ExistingLocalAddr  = $Existing.LocalAddress
  $Network.ExistingLocalPort  = $Existing.LocalPort
  $Network.ExistingRemoteAddr = $Existing.RemoteAddress
  $Network.ExistingRemotePort = $Existing.RemotePort
  $Network.ExistingOwningProc = $Existing.OwningProcess

  $Network.DNSCache = Get-DnsClientCache
  Write-Output "Network:"
  $Network | Format-Table
  $Network | Export-Csv -Path "data.csv"
  ipconfig /all
  ipconfig /all | Export-Csv -Path "data.csv"
}

#Network object data
function Get-NetworkObjects {
  $NetObj = @{}
  $NetShares = Get-SmbShare
  $NetObj.NetShareName = $NetShares.Name

  $NetPrinters = Get-Printer
  $NetObj.NetPrinterName = $NetPrinters.Name

  $NetPrinters = Get-Printer
  $NetObj.NetPrinterName = $NetPrinters.Name

  $NetObj.NetAccessProfiles = (netsh wlan show profiles)
  Write-Output "Network Objects:"
  $NetObj | Format-Table
  $NetObj | Export-Csv -Path "data.csv"
}

#Software data
function Get-Software {
  $Software = @{}
  $SoftwareInstalled = Get-WmiObject -Class Win32_Product
  $Software.SoftwareNames = $SoftwareInstalled.Name
  Write-Output "Software Installed:"
  $Software | Format-Table
  $Software | Export-Csv -Path "data.csv"
}

#Process data
function Get-Process {
  $Process = @{}
  $ProcessMain = Get-WmiObject Win32_Process
  $ProcessOwner = Get-Process
  $Process.ProcessName = $ProcessMain.Name
  $Process.ProcessID = $ProcessMain.ProcessID
  $Process.ParentProcessID = $ProcessMain.ParentProcessID
  $Process.ProcessLocation = $ProcessMain.Path
  $Process.ProcessOwner = $ProcessOwner.UserName
  Write-Output "Process:"
  $Process | Format-Table
  $Process | Export-Csv -Path "data.csv"
}

#Driver data
function Get-Driver {
  $Driver = @{}
  $DriverMain = Get-WindowsDriver -Online -All
  $Driver.DriverName = $DriverMain.Driver
  $Driver.BootCritical = $DriverMain.BootCritical
  $Driver.DriverLocation = $DriverMain.OriginalFileName
  $Driver.DriverVersion = $DriverMain.Version
  $Driver.DriverCreation = $DriverMain.Date
  $Driver.DriverProviderName = $DriverMain.ProviderName
  Write-Output "Driver:"
  $Driver | Format-Table
  $Driver | Export-Csv -Path "data.csv"
}

#File data
function Get-Files {
  Write-Output "Files:"
  Get-ChildItem -Path "C:\Users\*\Documents" -Recurse
  Get-ChildItem -Path "C:\Users\*\Documents" -Recurse | Export-Csv -Path "data.csv"
  Get-ChildItem -Path "C:\Users\*\Downloads" -Recurse
  Get-ChildItem -Path "C:\Users\*\Downloads" -Recurse | Export-Csv -Path "data.csv"
}

#Additional data
function Get-Additional {
  $Additional = @{}
  $AntiVirus = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct
  $ScheduledJob = Get-ScheduledJob
  $Command = Get-Command
  $Additional.AntiVirusName = $AntiVirus.DisplayName
  $Additional.ScheduledJobName = $ScheduledJob.Name
  $Additional.CommandName = $Command.Name
  Write-Output "Additional Info:"
  $Additional | Export-Csv -Path "data.csv"
  $Additional | Format-Table
}

function Main {
  $Creds = Get-Credential
  Get-Time
  Get-OS
  Get-Hardware
  Get-DC
  Get-HostAndDomain
  Get-Users
  Get-Boot
  Get-Task
  Get-Network
  Get-NetworkObjects
  Get-Software
  Get-Process
  Get-Driver
  Get-Files
  Get-Additional
}

Main
