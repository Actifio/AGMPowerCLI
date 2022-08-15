# Copyright 2022 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# Module manifest for module 'AGMPowerCLI'
#
# Generated by: Anthony Vandewerdt
#
# Generated on: 16/6/2020
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'AGMPowerCLI.psm1'

# Version number of this module.
ModuleVersion = '0.0.0.39'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '31f83a9e-9fe8-43b4-9a82-02325de71f2a'

# Author of this module
Author = 'Anthony Vandewerdt'

# Company or vendor of this module
CompanyName = 'Google'

# Copyright statement for this module
Copyright = '(c) 2022 Google, Inc. All rights reserved'

##################################################################################################################
# Description of the functionality provided by this module
Description = 'This is a community generated PowerShell Module for Actifio Global Manager (AGM).  
It provides a method to issue commands to AGM API endpoints, like "Application" and "Host".
This lets you create automation with AGM, or generate your own composite functions.
More information can be found here:  https://github.com/Actifio/AGMPowerCLI'

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '5.0'

# Name of the PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# ClrVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
    'Get-AGMAPIData',
    'Get-AGMAPIApplianceInfo',
    'Get-AGMAPIApplianceReport',
    'Post-AGMAPIData',
    'Put-AGMAPIData',
    'Connect-AGM',
    'Disconnect-AGM',
    'Convert-FromUnixDate',
    'Convert-ToUnixDate',
    'Convert-AGMDuration',
    'Get-AGMErrorMessage',
    'Test-AGMJSON',
    'Get-AGMAPILimit',
    'Get-AGMAppliance',
    'Get-AGMApplication',
    'Get-AGMApplicationCount',
    'Get-AGMApplicationActiveImage',
    'Get-AGMApplicationAppClass',
    'Get-AGMApplicationInstanceMember',
    'Get-AGMApplicationMember',
    'Get-AGMApplicationTypes',
    'Get-AGMApplicationWorkflow',
    'Get-AGMApplicationWorkflowStatus',
    'Get-AGMAudit',
    'Get-AGMCloudVM',
    'Get-AGMConsistencyGroup',
    'Get-AGMCredential',
    'Get-AGMDiskPool',
    'Get-AGMEvent',
    'Get-AGMHost',
    'Get-AGMImage',
    'Get-AGMImageCount',
    'Get-AGMImageSystemRecovery',
    'Get-AGMImageSystemStateOptions',
    'Get-AGMJob',
    'Get-AGMJobHistory',
    'Get-AGMJobStatus',
    'Get-AGMLDAPConfig',
    'Get-AGMLDAPGroup',
    'Get-AGMLogicalGroup',
    'Get-AGMLogicalGroupMember',
    'Get-AGMOrg',
    'Get-AGMRight',
    'Get-AGMRole',
    'Get-AGMSession',
    'Get-AGMSLT',
    'Get-AGMSLTPolicy',
    'Get-AGMSLP',
    'Get-AGMSLA',
    'Get-AGMTimeZoneHandling',
    'Get-AGMUser',
    'Get-AGMVersion',
    'Get-AGMVersionDetail',
    'Get-AGMWorkflow',
    'Import-AGMOnVault',
    'Import-AGMPDSnapshot',
    'New-AGMAppDiscovery',
    'New-AGMAppliance',
    'New-AGMCloudVM',
    'New-AGMCredential',
    'New-AGMHost',
    'New-AGMMount',
    'New-AGMOrg',
    'New-AGMRole',
    'New-AGMSLA',
    'Set-AGMAPIApplianceTask',
    'Save-AGMPassword',
    'Set-AGMCredential',
    'Set-AGMAPILimit',
    'Set-AGMHostPort',
    'Set-AGMImage',
    'Set-AGMTimeZoneHandling',
    'Set-AGMOrgApplication',
    'Set-AGMOrgHost',
    'Set-AGMOrgLogicalGroup',
    'Set-AGMSLA',
    'Remove-AGMAppliance',
    'Remove-AGMApplication',
    'Remove-AGMCredential',
    'Remove-AGMHost',
    'Remove-AGMHostPort',
    'Remove-AGMImage',
    'Remove-AGMJob',
    'Remove-AGMMigrate',
    'Remove-AGMMount',
    'Remove-AGMOrg',
    'Remove-AGMRole',
    'Remove-AGMSLA',
    'Remove-AGMUser',
    'Restore-AGMApplication',
    'Start-AGMReplicateLog',
    'Start-AGMMigrate',
    'Update-AGMOrg',
    'Get-GoogleCloudBackupDRConsole')

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = '*'

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @("Actifio","AGM","Sky","CDS","CDX","VDP")

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/Actifio/AGMPowerCLI/blob/main/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/Actifio/AGMPowerCLI'

        # A URL to an icon representing this module.
        IconUri = 'https://i.imgur.com/QAaK5Po.jpg'

        # ReleaseNotes of this modulegte
        ReleaseNotes = '
        ## [0.0.0.39] 2022-07-22
        Default timeout of 60 seconds is causing timeouts on GCE Instance operations.   Increasing to 300 seconds
        Remove-AGMSLA will error if a non-protected Appid is specified rather than requesting an SLA ID

        ## [0.0.0.38] 2022-06-29
        Added support for Org ID to new-Host and new-credential.   Added support for OnVault pool in new-credential while improving logic.  Added secretkey support to new-host, renamed Get-GBDRConsole to Get-GoogleCloudBackupDRConsole

        ## [0.0.0.37] 2022-06-15
        Add New-AGMHost, Set-AGMHostPort,  Remove-AGMHostPort, update license info
        Teach Get-AGMHost to show extra info when ID is specified

        ## [0.0.0.36] 2022-04-22
        Add Import-AGMPDSnapshot,   allowed user to set timeout with -agmtimeout and set default to 60 seconds

        ## [0.0.0.35] 2022-04-13
        Option -o to show filterable fields did not work on PS 5.

        ## [0.0.0.34] 2022-04-13
        Add Appliance API commands:  Get-AGMAPIApplianceInfo, Get-AGMAPIApplianceReport, Set-AGMAPIApplianceTask

        ## [0.0.0.33] 2022-03-30
        Add Get-AGMImageSystemRecovery

        ## [0.0.0.32] 2022-01-07
        Handle empty packet return error line 544
        Changed default timeout to 20 seconds

        ## [0.0.0.31] 2021-10-11
        Add Remove-AGMAppliance and New-AGMAppliance

        ## [0.0.0.30] 2021-09-15
        Taught Get-AGMCloudVM to use offset and limit correctly, it was only fetching 10 VMs before this and ignoring the limit

        ## [0.0.0.29] 2021-09-13
        Allow silent install
        Teach Remove-AGMImage to use force=false 
        Teach Set-AGMImage to change expiration
        Teach Get-AGMImage and Set-AGMImage and Remove-AGMImage to work with both imagename and backupname

        ## [0.0.0.28] 2021-09-12
        Added Get-AGMApplicationCount
        Told Get-AGMSLA to stop allowing -o, as this endpoint cannot be queried for filterable fields

        ## [0.0.0.27] 2021-09-08
        New-AGMCredential was missed from the PSD1 file.   Corrected this

        ## [0.0.0.26] 2021-08-24
        Added Remove-AGMCredential, New-AGMCredential, Set-AGMCredential, Get-AGMImageCount, New-AGMCloudVM, Get-AGMCloudVM
        Updated Get-AGMCredential to allow individual credential to be selected
        Updated Convert-FromUnixDate to handle empty fields 

        ## [0.0.0.25] 2021-07-14
        Teach Set-AGMSLA how to work with logical groups
        Fix issue with Get-AGMLogicalGroupMember where groups with more than 1 member get no output
        Teach the Get functions to allow both ID and say slaid for SLAs, or appid for apps.
        Add Start-AGMReplicateLog 

        ## [0.0.0.24] 2021-07-12  
        Improve help text for Remove-AGMMount 
        Add Set-AGMimage to allow user to set labels

        ## [0.0.0.23] 2021-06-28    
        Add Get-AGMCredential 

        ## [0.0.0.22] 2021-06-28
        Teach Remove-AGMMount about preservevm
        Fix install bug on Linux OS on line 80 of Install-AGMPowerLib.ps1

        ## [0.0.0.21] 2020-12-04
        Teach Remove-AGMHost about clusterIDs

        ## [0.0.0.20] 2020-12-03
        Improve output of filter value options when shown with -o, they are now alpha sorted, format nicer and dont get JSON layer error if the list is too long

        ## [0.0.0.19] 2020-10-29
        Add New-AGMAppDiscovery

        ## [0.0.0.18] 2020-10-28
        Add Remove-AGMHost

        ## [0.0.0.17] 2020-10-13
        Add duration conversion routine to job, jobstatus and jobhistory

        ## [0.0.0.16] 2020-09-20
        Improved module description for PowerShell Gallery users
        Added more help information

        ## [0.0.0.13] 2020-09-18
        Add Get-AGMAPILimit, fix issue with Set-AGMAPILimit in PS5

        ## [0.0.0.12] 2020-09-18
        Allow this module to be run by PS5

        ## [0.0.0.11] 2020-09-07
        Get-AGMApplicationWorkflowStatus was being truncated by item column

        ## [0.0.0.10] 2020-09-5
        Added Restore-AGMApplication
        Changed most variables from int to string as their size can exceed int very easily

        ## [0.0.0.9] 2020-08-24
        Added Import-AGMOnVault   
        Support not equals filter method

        ## [0.0.0.8] 2020-08-21
        Added New-AGMSLA, Remove-AGMSLA, Set-AGMSLA, Remove-AGMMigrate, Start-AGMMigrate, Get-AGMImageSystemStateOptions
        Better handle case where -o does not fetch correctly formated filtervalues
        
        ## [0.0.0.7] 2020-07-20
        Split modules so non-base functions are in AGMPowerLib'

        # Prerelease string of this module
        # Prerelease = ''

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        # ExternalModuleDependencies = @()

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

