
# Usage Examples
This document contains usage examples that include both AGMPowerCLI and AGMPowerLIB commands.

**[AGM](#agm)**<br>
>**[AGM Version](#agm-version)**<br>

**[Appliances](#appliances)**<br>
>**[Appliance Add And Remove (Actifio only)](#appliance-add-and-remove-actifio-only)**<br>
**[Appliance Discovery Schedule (10.0.4 to 11.0.3)](#appliance-discovery-schedule-1004-to-1103)**<br>
**[Appliance Info And Report Commands (10.0.4 to 11.0.3)](#appliance-info-and-report-commands-1004-to-1103)**<br>
**[Appliance Logs (10.0.4 to 11.0.3)](#appliance-logs-1004-to-1103)**<br>
**[Appliance Parameter and Slot Management (10.0.4 to 11.0.3)](#appliance-parameter-and-slot-management-1004-to-1103)**</br>
**[Appliance Parameter and Slot Management](#appliance-parameter-and-slot-management)**</br>
**[Appliance Schedule Management](#appliance-schedule-management)**</br>
**[Appliance Timezone (10.0.4 to 11.0.3)](#appliance-timezone-1004-to-1104)**<br>

**[Applications](#applications)**<br>
>**[Application IDs](#application-ids)**<br>
**[Counting your Applications](#counting-your-applications)**<br>
**[Application Discovery](#application-discovery)**<br>
**[Listing AppTypes](#listing-apptypes)**<br>
**[Find Images for a particular application](#find-images-for-a-particular-application)**<br>
**[Find the Latest Image For a Particular Application](#find-the-latest-image-for-a-particular-application)**<br>
**[Removing an Application](#removing-an-application)**</br>

**[Audit](#audit)**</br>
>**[Exploring the Audit Log](#exploring-the-audit-log)**</br>
**[Finding the Last Command a User Issued](#finding-the-last-command-a-user-issued)**</br>

**[Backup Plans](#backup-plans)**</br>
>**[Applying a Backup Plan](#applying-a-backup-plan)**</br>
**[Disabling a Backup Plan](#disabling-a-backup-plan)**</br>
**[Backup Plan Enablement Status](#backup-plan-enablement-status)**</br>
**[Backup Plan Policy Usage](#backup-plan-policy-usage)**</br>
**[Backup Plan Policy Usage By Application](#backup-plan-policy-usage-by-application)**</br>
**[Backup Plan Removal](#backup-plan-removal)**</br>
**[Backup Plan Removal in Bulk](#backup-plan-removal-in-bulk)**</br>
**[Importing and Exporting Policy Templates](#importing-and-exporting-policy-templates)**</br>

**[Billing](#billing)**</br>
>**[Backup SKU Usage](#backup-sku-usage)**</br>

**[Compute Engine Instances](#compute-engine-instances)**<br>
>**[Compute Engine Cloud Credentials](#compute-engine-cloud-credentials)**<br>
**[Compute Engine Instance Discovery](#compute-engine-instance-discovery)**<br>
**[Compute Engine Instance Onboarding Automation](#compute-engine-instance-onboarding-automation)**<br>
**[Compute Engine Instance Management](#compute-engine-instance-management)**<br>
**[Compute Engine Instance Conversion from VMware VM](#compute-engine-instance-conversion-from-vmware-vm)**</br>
**[Compute Engine Instance Multi Conversion from VMware VM](#compute-engine-instance-multi-conversion-from-vmware-vm)**</br>
**[Compute Engine Instance Mount](#compute-engine-instance-mount)**<br>
**[Compute Engine Instance Multi Mount Disaster Recovery](#compute-engine-instance-multi-mount-disaster-recovery)**<br>
**[Compute Engine Instance Image Audit](#compute-engine-instance-image-audit)**<br>

**[Connecting or Logging in](#connecting-or-logging-in)**<br>
>**[Connect-AGM](#connect-agm)**</br>

**[Consistency Groups](#consistency-groups)**<br>
>**[Consistency Group Management](#consistency-group-management)**<br>

**[DB2](#db2)**</br>
>**[Creating a DB2 mount](#creating-a-db2-mount)**</br>

**[Disaster Recovery Automation](#disaster-recovery-automation)**</br>
>**[Recovering Virtual Machines](#recovering-virtual-machines)**</br>
>**[Recovering Databases](#recoverying-databases)**</br>

**[Events](#events)**</br>
>**[Listing Your Events](#listing-your-events)**</br>

**[FileSystem](#filesystem)**</br>
>**[Creating a FileSystem mount](#creating-a-filesystem-mount)**</br>

**[Hosts](#hosts)**<br>
>**[Adding a Host](#adding-a-host)**<br>
**[Finding a Host ID by Host Name](#finding-a-host-id-by-host-name)**<br>
**[Finding a Host ID by Operating System Type](#finding-a-host-id-by-operating-system-type)**<br>
**[Listing Your Hosts](#listing-your-hosts)**<br>
**[Managing Host Ports](#managing-host-ports)**</br>
**[Deleting a Host](#deleting-a-host)**</br>
**[Deleting Stale Hosts](#deleting-stale-hosts)**</br>

**[Images](#images)**<br>
>**[Image Creation With An On-Demand Job](#image-creation-with-an-ondemand-job)**<br>
**[Image Creation In Bulk Using Policy ID](#image-creation-in-bulk-using-policy-id)**<br>
**[Image Expiration](#image-expiration)**<br>
**[Image Expiration In Bulk](#image-expiration-in-bulk)**<br>
**[Image Expiration For a Deleted Cloud Storage Bucket](#image-expiration-for-a-deleted-cloud-storage-bucket)**<br>
**[Image Import From OnVault](#image-import-from-onvault)**<br>
**[Persistent Disk Import From OnVault](#persistent-disk-import-from-onvault)**<canc>
**[Image Restore](#image-restore)**<br>
**[Setting an Image Label](#setting-an-image-label)**</br>
**[Setting an Image Label in Bulk](#setting-an-image-label-in-bulk)**</br>

**[Installation](#installation)**<br>

**[Jobs](#jobs)**<br>
>**[Display Job History](#displaying-job-history)**</br>
**[Finding Running Jobs](#finding-running-jobs)**<br>
**[Canceling a Running Job](#canceling-a-running-job)**<br>
**[Following a Running Job](#following-a-running-job)**<br>

**[Logical Groups](#logical-groups)**<br>
>**[Listing Your Logical Groups](#listing-your-logical-groups)**<br>
**[Listing members in a Logical Group](#listing-members-in-a-logical-group)**</br>

**[LVM](#lvm)**</br>
>**[Create a new LVM mount](#create-a-new-lvm-mount)**</br>

**[Mount](#mount)**</br>
>**[Active Mounts](#active-mounts)**</br>
**[Create a new mount](#create-a-new-mount)**</br>
**[Create a new mount to a Container](#create-a-new-mount-to-a-container)**</br>
**[Display Container Mount YAML](#display-container-mount-yaml)**</br>
**[Multi Mount for Ransomware Analysis](#multi-Mount-for-ransomware-analysis)**</br>
**[Unmounting an Image](#unmounting-an-image)**</br>

**[MySQL](#mysql)**</br>
>**[Creating a MySQL mount](#creating-a-mysql-mount)**</br>

**[Oracle](#oracle)**</br>
>**[Creating a Oracle mount](#creating-a-oracle-mount)**</br>

**[Organizations](#organizations)**<br>
>**[Organization Creation](#organization-creation)**<br>

**[PostgreSQL](#postgresql)**</br>
>**[Creating a PostgresSQL mount](#creating-a-postgresql-mount)**</br>

**[SAP HANA](#sap-hana)**</br>
>**[SAP HANA Mount](#sap-hana-mount)**</br>
**[SAP HANA Multi Mount](#sap-hana-multi-mount)**</br>
**[SAP HANA Restore](#sap-hana-restore)**</br>

**[SQL Server](#sql-server)**</br>
>**[SQL Server Database Mount](#sql-server-database-mount)**</br>
**[SQL Server Database Clone](#sql-server-database-clone)**</br>
**[SQL Server Database Mount with point in time recovery](#sql-server-database-mount-with-point-in-time-recovery)**</br>
**[SQL Server Database Mount and Migrate](#sql-server-database-mount-and-migrate)**</br>
**[SQL Server Instance Mount](#sql-server-instance-mount)**</br>
**[SQL Server Multi Mount and Migrate](#sql-server-multi-mount-and-migrate)**</br>
**[SQL Server Protecting and Rewinding Child Apps](#sql-server-protecting-and-rewinding-child-apps)**</br>

**[Storage Pools](#storage-pools)**</br>
>**[Listing Your Storage Pools](#listing-your-storage-pools)**</br>

**[VMware](#vmware)**</br>
>**[Using a VMware mount to create a new VMware VM](#using-a-vmware-mount-to-create-a-new-vmware-vm)**</br>
**[Mounting a VMware VM backup to an existing VM](#mounting-a-vmware-vm-backup-to-an-existing-vm)**</br>
**[VMware Multi Mount](#vmware-multi-mount)**</br>

**[Workflows](#Workflows)**</br>
>**[Checking the Status of a Workflow](#checking-the-status-of-a-workflow)**</br>
**[Running a Workflow](#running-a-workflow)**</br>


# AGM

An AGM or Actifio Global Manager is the management end point for all our activities.  We login to the AGM with ```Connect-AGM``` and then issue our commands.   Google Cloud Backup and DR uses a Management Console which performs the same function.

## AGM Login

We login with the ```Connect-AGM``` command but the exact syntax will vary:

| Product | Device 
| ---- | ---- 
| Actifio | [Actifio Global Manager](README.md/#4-Login-to-your-AGM)
| Google Cloud Backup and DR | [Management Console](GCBDR.md)


## AGM Version

The following command will display the version.   It can also be used as a simple command to confirm connectivity:
```
Get-AGMVersion
```

[Back to top](#usage-examples)

# Appliances

An Appliance does the work of creating backups.  There are two kinds of Appliance depending on which product you are using.  These commands apply to both unless otherwise stated.

| Product | Device 
| ---- | ---- 
| Actifio | Sky
| Google Cloud Backup and DR | Backup/recovery appliance 

## Appliance add and remove (Actifio only)

> **Note**:   You cannot perform appliance add and remove in Google Cloud Backup and DR.  This is for Actifio only.

You may want to add or remove a Sky Appliance from the AGM Web GUI.   You can list all the Sky Appliances with this command:
```
Get-AGMAppliance | select id,name,ipaddress
```
Output should look like this:
```
id    name       ipaddress
--    ----       ---------
7286  backupsky1 10.194.0.20
45408 backupsky2 10.194.0.38
```
We can then remove the Sky Appliance by specifying the ID of the appliance with this command:
```
Remove-AGMAppliance 45408
```
We list the appliances with:
```
Get-AGMAppliance | select id,name,ipaddress
```
Output should look like this:
```
id   name       ipaddress
--   ----       ---------
7286 backupsky1 10.194.0.20
```
We can add the Sky Appliance back with this command.  Note we can do a dryrun to make sure the add will work, but you don't need to.  The main thing with a dry run is we need to see an approval token because that is key to actually adding the appliance.  
```
New-AGMAppliance -ipaddress 10.194.0.38 -username admin -password password -dryrun | select-object approvaltoken,cluster,report
```
Output should look like this:
```
approvaltoken          cluster                                                      report
-------------          -------                                                      ------
05535A005F051E00480608 @{clusterid=141925880424; ipaddress=10.194.0.38; masterid=0} {"errcode":0,"summary":"Objects to be imported:\n\t.....
```
This is the same command but without the dryrun:
```
New-AGMAppliance -ipaddress 10.194.0.38 -username admin -password password  | select-object cluster,report
```
Output should look like this:
```
cluster                                                                                                               report
-------                                                                                                               ------
@{id=45582; href=https://10.194.0.3/actifio/cluster/45582; clusterid=141925880424; ipaddress=10.194.0.38; masterid=0} {"errcode":0,"summary"...
```
We list the appliances with:
```
Get-AGMAppliance | select id,name,ipaddress
```
Output should look like this:
```
id    name       ipaddress
--    ----       ---------
45582 backdrsky2 10.194.0.38
7286  backupsky1 10.194.0.20
```
## Appliance Discovery Schedule (10.0.4 to 11.0.3)

> **Warning**:   This method will be deprecated in a future release and replaced with [Appliance Schedule Management](UsageExamples.md/#appliance-schedule-management)

To set the start time when auto discovery runs (instead of the default 2am), first learn the appliance ID:
```
Get-AGMAppliance | select id,name
```
Output should look like this:
```
id     name
--     ----
591780 backup-server-67154
406219 backup-server-29736
```
Display if an existing schedule is set (if no schedule is shown, then the default of 2am is in use):
```
$applianceid = 406219
Get-AGMAPIApplianceInfo -applianceid $applianceid -command getschedule -arguments "name=autodiscovery"
```
Output should look like this:
```
time  frequency
----  ---------
10:00 daily
```
To set the schedule use the following syntax.  In this example we set it to 9am rather than 10am.
```
$applianceid = 406219
Set-AGMAPIApplianceTask -applianceid $applianceid -command setschedule -arguments "name=autodiscovery&frequency=daily&time=09:00"
```
Output should look like this:
```
status
------
     0
```
Check schedule with this command:
```
Get-AGMAPIApplianceInfo -applianceid $applianceid -command getschedule -arguments "name=autodiscovery"
```
Output should look like this:
```
time  frequency
----  ---------
09:00 daily
```

## Appliance Info And Report Commands (10.0.4 to 11.0.3)

> **Warning**:   This method will be deprecated in a future release and replaced with [Appliance Schedule Management](UsageExamples.md/#appliance-schedule-management) and [UsageExamples.md/#Appliance Parameter and Slot Management](appliance-parameter-and-slot-management). 
> 
> **Note**:   If you want to manage appliance parameters such as slots, use the **Get-AGMLibApplianceParameter** and **Set-AGMLibApplianceParameter** commands documented [here](#appliance-parameter-and-slot-management).

You can run info and report commands on an appliance using AGMPowerCLI.  To do this we need to tell the Management Console which appliance to run the command on. So first learn your appliance ID with ```Get-AGMAppliance```.  In this example the appliance we want to work with is ID 70194.
```
Get-AGMAppliance | select id,name
```
Output should look like this:
```
id     name
--     ----
406219 backup-server-29736
70194  backup-server-32897
```
### Running info commands
We can use ```Get-AGMAPIApplianceInfo``` to send info (also known as udsinfo) commands.   In this example we send the ```udsinfo lshost``` command to the appliance with ID 70194.
```
Get-AGMAPIApplianceInfo -applianceid 70194 -command lshost | select id,hostname
```
Output should look like this:
```
id     hostname
--     --------
16432  tiny
57610  winsrv2019-1
57612  winsrv2019-2
```
To get info about a specific host ID, you could use this command:
```
Get-AGMAPIApplianceInfo -applianceid 70194 -command lshost -arguments "argument=16432"
```
You can also filter by using a command like this:
```
Get-AGMAPIApplianceInfo -applianceid 70194 -command lshost -arguments "filtervalue=hostname=tiny"
```

### Running report commands

We can use ```Get-AGMAPIApplianceReport``` to send report commands.  If you want to know which commands you can send, start with ```reportlist```.
```
Get-AGMAPIApplianceReport -applianceid 70194 -command reportlist
```
Output should look like this:
```
ReportName             ReportFunction                                                                           RequiredRoleRights
----------             --------------                                                                           ------------------
reportadvancedsettings Show all Advanced policy options that have been set                                      AdministratorRole
```
In this example we run the ```reportapps``` command:
```
Get-AGMAPIApplianceReport -applianceid 70194 -command reportapps | select hostname,appname,"MDLStat(GB)"
```
Output should look like this:
```
HostName      AppName            MDLStat(GB)
--------      -------            -----------
tiny          tiny               20.000
windows       windows            50.000
win-target    win-target         50.000
postgres1melb postgresql_5432    0.046
sap-prod      act                70.000
windows       WINDOWS\SQLEXPRESS 0.437
centos1       centos1            4.051
centos2       centos2            3.855
centos3       centos3            4.098
ubuntu1       ubuntu1            29.199
ubuntu2       ubuntu2            31.855
ubuntu3       ubuntu3            26.191
winsrv2019-1  WinSrv2019-1       37.332
winsrv2019-2  WinSrv2019-2       36.062
```
We then send an argument of ```-a tiny``` to restrict the output to applications with a name of **tiny**
```
Get-AGMAPIApplianceReport -applianceid 70194 -command reportapps -arguments "-a tiny" | select hostname,appname,"MDLStat(GB)"
```
Output should look like this:
```
HostName AppName MDLStat(GB)
-------- ------- -----------
tiny     tiny    20.000
```
#### Running a command with multiple arguments
If you need to send multiple arguments separate them with an **&**, for example, this command sends the **reportimages** command to appliance ID 406219 with the **-a 0** and **-s** parameters and exports it to CSV.
```
Get-AGMAPIApplianceReport -applianceid 406219 -command reportimages -arguments "-a 0&-s" |  Export-Csv disks.csv
```

## Appliance Logs (10.0.4 to 11.0.3)

We can fetch logs from an Appliance with the following command:
```
Get-AGMLibApplianceLogs -logtype "udppm,psrv"
```
A zip file will download in the folder you ran the command in.

* If you don't know what log types to download, just run the command without parameters.
* If you have more than one appliance you will need to specify which appliance to download from with ```-applianceid xxxx``` You can learn applianceID with ```Get-AGMAppliance```
* You can download agent (connector) logs by specifying the host ID with ```-hostid xxx``` and ```-logtypes "agent"``` or for AGM, ```-logtypes "connector"```   Learn host ID with ```Get-AGMHost```
* You can also use ```-startdate``` and ```-enddate``` for instance ```-startdate "2022-10-01" -enddate "2022-10-04"```


## Appliance Parameter and Slot Management (10.0.4 to 11.0.3)

> **Warning**:   This method will be deprecated in a future release and replaced with [Appliance Schedule Management](UsageExamples.md/#appliance-schedule-management) and [UsageExamples.md/#Appliance Parameter and Slot Management](appliance-parameter-and-slot-management). 

Each appliance has a set of parameters that are used to:

* Enable and disable functions.  These parameters are usually: 0 (off) or 1 (on)
* Set slot limits to control concurrently running jobs
* Set values such as timeouts

### Displaying and setting parameters

If you have a single appliance then you can run this command to display all available parameters:
```
Get-AGMLibApplianceParameter
```
If you have multiple appliances then learn the appliance ID of the relevant appliance and then use that ID, like this:
```
Get-AGMAppliance | select id,name
```
Output should look like this:
```
id     name
--     ----
406219 backup-server-29736
406230 backup-server-32142
```
Now get the parameters for your selected appliance:
```
Get-AGMLibApplianceParameter -applianceid 406219
```
Output should look like this:
```
enableexpiration                      : 1
< output truncated>
```
To display a specific parameter use syntax like this (you may need the **-applianceid** parameter):
```
Get-AGMLibApplianceParameter -param enablescheduler
```
To set a parameter use syntax like this (you may need the **-applianceid** parameter).  In this example we disable the scheduler by setting it to 0:
```
Get-AGMLibApplianceParameter -param enablescheduler
Set-AGMLibApplianceParameter -param enablescheduler -value 0
```
### Changing maximum backup jobs per host (appliance level - affects all hosts)

There is a system parameter that controls the maximum number of backup jobs that can be run against every host on that appliance. By default this value is 1, meaning a maximum of one backup job can be run per host. Scheduled jobs will queue behind the running job. Ondemand jobs with the -queue option will join the queue waiting for the running job to finish.

You can display and change this setting using the following command (you may need the **-applianceid** parameter).  In this example we allow 2 backup jobs per host:
```
Get-AGMLibApplianceParameter -param backupjobsperhost
Set-AGMLibApplianceParameter -param backupjobsperhost -value 2
```
### Changing maximum mount jobs per host (appliance level - affects all hosts)

By default only one mount job can run on a host at one point in time.

This value can be displayed using this syntax (you may need the **-applianceid** parameter):
```
Get-AGMLibApplianceParameter -param maxconcurrentmountsperhost
```
It can be changed with syntax like this (you may need the **-applianceid** parameter).  In this example we allow two concurrent mount jobs per host:
```
Set-AGMLibApplianceParameter -param maxconcurrentmountsperhost -value 2
```
Note this is a system wide parameter. There is no way to set this on a per host basis.

### Changing maximum mount and backup jobs per appliance using slots (appliance level - affects all hosts)

Each backup appliance uses a pacing mechanism known as *slots* to manage the number of jobs that can run simultaneously on that appliance.   This means that if has a policy has more applications attempting to start a backup job than there are available slots, that the appliance running your jobs may hit a slot limit, resulting in the excess jobs over the slot limit going into *queued* status, waiting for free slots, rather than starting immediately.    There is nothing inherently wrong this, its simply a form of *pacing*.

To manage this we can adjust what are called slot values.  Note that while we are using AGMPowerLib commands to do this, you need to ensure your AGMPowerCLI is on version 0.0.0.35 or higher.   You can check your AGMPowerCLI version with this command:
**Get-Command -module AGMPowerCLI**

Firstly learn the ID of the relevant Appliance.  In this case the appliance running our jobs is **project1sky** so we will use applianceid **361153**
```
Get-AGMAppliance | select id,name
```
Output should look like this:
```
id     name
--     ----
361153 project1sky
296357 londonsky.c.project1.internal
```
Now depending on which job type, we modify different slots.

#### Slot limits for mount jobs
We need to learn the current value of the params that relate to **dataaccess** slots. This is because a mount job is an data access job, meaning each mount job uses one data access slot while it is running.  There are three relevant slots:
* **reserveddataaccessslots** This is the guaranteed number of data access jobs that can run at any time.  
* **maxdataaccessslots** This controls the maximum number of data access jobs that can run at any time.  
* **unreservedslots** Unreserved slots are used if all the reserved slots are in use but more jobs wants to run up to the maximum number for that type.

We learn the values with:
```
Get-AGMLibApplianceParameter -applianceid 361153 -param reserveddataaccessslots
Get-AGMLibApplianceParameter -applianceid 361153 -param maxdataaccessslots
Get-AGMLibApplianceParameter -applianceid 361153 -param unreservedslots
```
Here is an example:
```
Get-AGMLibApplianceParameter -applianceid 361153 -param reserveddataaccessslots
```
Output should look like this:
```
reservedondemandslots
---------------------
3
```
We can set the slots to different values like this:
```
Set-AGMLibApplianceParameter -applianceid 361153 -param reserveddataaccessslots -value 10
Set-AGMLibApplianceParameter -applianceid 361153 -param maxdataaccessslots -value 15
Set-AGMLibApplianceParameter -applianceid 361153 -param unreservedslots -value 15
```
Here is an example:
```
Set-AGMLibApplianceParameter -applianceid 361153 -param reserveddataaccessslots -value 10
```
Output should look like this:
```
reservedondemandslots changed from 3 to 10
```
#### Slot limits for OnVault jobs
We need to learn the current value of the params that relate to **onvault** slots.  Note this is listed as **vault**
* **reservedvaultslots** This is the guaranteed number of OnVault jobs that can run at any time.  
* **maxvaultslots** This controls the maximum number of OnVault jobs that can run at any time.  
* **unreservedslots** Unreserved slots are used if all the reserved slots are in use but more jobs wants to run up to the maximum number for that type.

We learn the values with:
```
Get-AGMLibApplianceParameter -applianceid 361153 -param reservedvaultslots
Get-AGMLibApplianceParameter -applianceid 361153 -param maxvaultslots
Get-AGMLibApplianceParameter -applianceid 361153 -param unreservedslots
```
We can set the slots to different values like this:
```
Set-AGMLibApplianceParameter -applianceid 361153 -param reservedvaultslots -value 10
Set-AGMLibApplianceParameter -applianceid 361153 -param maxvaultslots -value 15
Set-AGMLibApplianceParameter -applianceid 361153 -param unreservedslots -value 15
```
#### Slot limits for snapshot jobs
We need to learn the current value of the params that relate to **snapshot** slots.
* **reservedsnapslots** This is the guaranteed number of snapshot jobs that can run at any time.  
* **maxsnapslots** This controls the maximum number of snapshot jobs that can run at any time.  
* **unreservedslots** Unreserved slots are used if all the reserved slots are in use but more jobs wants to run up to the maximum number for that type.

We learn the values with:
```
Get-AGMLibApplianceParameter -applianceid 361153 -param reservedsnapslots
Get-AGMLibApplianceParameter -applianceid 361153 -param maxsnapslots
Get-AGMLibApplianceParameter -applianceid 361153 -param unreservedslots
```
We set the slots to different values like this:
```
Set-AGMLibApplianceParameter -applianceid 361153 -param reservedsnapslots -value 10
Set-AGMLibApplianceParameter -applianceid 361153 -param maxsnapslots -value 15
Set-AGMLibApplianceParameter -applianceid 361153 -param unreservedslots -value 15
```
## Appliance Parameter and Slot Management

> **Warning**:   This method will be enabled in a future release.

First learn the ID and Appliance ID of the relevant appliance (you will need both IDs, where the appliance ID is also referred to as the cluster ID):
```
Get-AGMAppliance | select id,name,@{N='applianceid'; E={$_.clusterid}}

id   name              applianceid
--   ----              -----------
7188 appliance-1-83040 142700167048
```
You can learn the current setting for a parameter with this command (showing typical output using the ID of the Appliance):
```
Get-AGMApplianceParameter -id 7188 -parameter maxsnapslots

@type      : parameterRest
id         : maxsnapslots
href       : http://bmc-804817621514-dot-us-central1.backupdr.googleusercontent.com/actifio/cluster/142700167048/parameter/maxsnapslots
cluster    : @{id=7188; href=http://bmc-804817621514-dot-us-central1.backupdr.googleusercontent.com/actifio/cluster/7188; clusterid=142700167048; ipaddress=10.68.0.3}
paramvalue : 8
```
We can change the value and confirm.  Note the GET command uses ID of the Appliance while the SET command uses the applianceid, so here we use the applianceID:
```
Set-AGMApplianceParameter -applianceid 142700167048 -parameter maxsnapslots -value 10
Get-AGMApplianceParameter -id 7188 -parameter maxsnapslots

@type      : parameterRest
id         : maxsnapslots
href       : http://bmc-804817621514-dot-us-central1.backupdr.googleusercontent.com/actifio/cluster/142700167048/parameter/maxsnapslots
cluster    : @{id=7188; href=http://bmc-804817621514-dot-us-central1.backupdr.googleusercontent.com/actifio/cluster/7188; clusterid=142700167048; ipaddress=10.68.0.3}
paramvalue : 10

```
## Appliance Schedule Management 

> **Warning**:   This method will be enabled in a future release.

First learn the ID of the Appliance you want to set the schedule on.
```
Get-AGMAppliance | select id,name

id   name
--   ----
7188 appliance-1-83040
```
Now use that ID to query the current schedule.  You may not get a schedule if none has been set:
```
Get-AGMApplianceSchedule -id 7188 -schedulename "autodiscovery"

time  repeatinterval frequency
----  -------------- ---------
16:00 1              daily
```
You can set or change the schedule with syntax like this:
```
Set-AGMApplianceSchedule -id 7188 -schedulename "autodiscovery" -frequency "daily" -time "20:00"
Get-AGMApplianceSchedule -id 7188 -schedulename "autodiscovery"

time  repeatinterval frequency
----  -------------- ---------
20:00 1              daily
```

## Appliance timezone (10.0.4 to 11.0.3)
To display Appliance timezone, learn the appliance ID and then query the relevant appliance:
```
Get-AGMAppliance | select id,name
```
Output should look like this:
```
id     name
--     ----
591780 backup-server-67154
406219 backup-server-29736

Get-AGMAppliance 406219 | select timezone
```
Output should look like this:
```
timezone
--------
UTC
```
To set Appliance timezone, use the following syntax, making sure to specify a valid timezone:

```
$timezone = "Australia/Sydney"
$applianceid = 406219
Set-AGMAPIApplianceTask -applianceid $applianceid -command "chcluster" -arguments "timezone=$timezone&argument=11"
```
Output should look like this:
```
status
------
     0

```
Now wait 3 minutes (this takes a little time to update).   If you see the old timezone, please wait a little longer.
```
Get-AGMAppliance 406219 | select timezone
```
Output should look like this:
```
timezone
--------
Australia/Sydney
```
[Back to top](#usage-examples)

# Applications

Applications are effectively data sources.  They contain the data we want to backup.

## Application IDs

The most common requirement for many commands is to supply the application ID, which is a unique number for each application.   This command is the default choice however if you run it without [filters](README.md/#filtering) or select statements you will be overwhelmed:
```
Get-AGMApplication
```
So you could use a command like this to find a host called ```bastion```:
```
$appname = "bastion"
Get-AGMApplication -filtervalue appname=$appname | select id,appname,apptype
```
Output would look like this:
```
id     appname apptype
--     ------- -------
709575 bastion GCPInstance
```
An alternative is to use this command:
```
Get-AGMLibApplicationID
```
Lets say we are looking for a host called ```bastion```.   We could use a command like this and get the key information we need:
```
Get-AGMLibApplicationID -appname bastion

id            : 709575
friendlytype  : GCP Instance
hostname      : bastion
hostid        : 709573
appname       : bastion
appliancename : backup-server-29736
applianceip   : 10.0.3.29
applianceid   : 144091747698
appliancetype : Sky
managed       : True
slaid         : 965514
```
There are many search options, for instance if you don't know the full name you can ```-fuzzy``` like this:
```
Get-AGMLibApplicationID -appname bastio -fuzzy
```
## Counting Your Applications
A very simple way to count the total number of applications is with a command like this, which will return a number.

In this example we have 99 applications:
```
Get-AGMApplicationCount
99  
```   
We now add filters, first to see how many are managed (have a backup plan applied:
```
Get-AGMApplicationCount -filtervalue managed=true
22
```
Then we look for VMware VMs:
```
Get-AGMApplicationCount -filtervalue apptype=VMBackup
50
```
And see how many of them have backup plans:
```                                                                                                                               
Get-AGMApplicationCount -filtervalue "apptype=VMBackup&managed=true"
4
```

## Application Discovery
To run application discovery against a host we need to know the host ID and the Appliance ID.  Then run this:
```
New-AGMAppDiscovery -hostid 5678 -applianceid 1415071155
```

## Listing AppTypes
If we want to learn what apptypes we are currently working with, we can list them with this command:
```
Get-AGMApplicationTypes
```
Output will look like this:
```
CIFS                                                                                                                                                                                     ConsistGrp
FileSystem
GCPInstance
NFS
POSTGRESQL
POSTGRESQLInstance
SAPHANA
SqlInstance
SqlServerWriter
VMBackup
```
## Find Images for a particular application

If we know the application ID, we can find any images for that application with this command:
```
$appid = 709575
Get-AGMLibImageDetails -appid $appid
```
Output will look like this (backupname is the same thing as imagename).
```
backupname    jobclass consistencydate     endpit
----------    -------- ---------------     ------
Image_0177198 snapshot 2022-11-10 09:22:36
Image_0184241 snapshot 2022-11-11 06:00:14
Image_0185325 snapshot 2022-11-11 09:05:46
Image_0189474 snapshot 2022-11-14 13:59:12
Image_0192543 snapshot 2022-11-15 08:34:40
Image_0196638 snapshot 2022-11-16 08:46:17
```

## Find the Latest Image For a Particular Application
If we want to know the most recent image created for a particular application we can use this command:
```
$appid = 709575
Get-AGMLibLatestImage -appid $appid
```
Output will look like this (backupname is the same thing as imagename).
```
appliance       : backup-server-29736
hostname        : bastion
appname         : bastion
appid           : 709575
jobclass        : snapshot
backupname      : Image_0196638
id              : 984504
consistencydate : 2022-11-16 08:46:17
endpit          :
sltname         : pd-snaps-multiregional
slpname         : backup-server29736_Profile
policyname      : daily snap
```
The default is for snapshot, but you can also specify a jobclass:
* ```-jobclass OnVault``` To look for OnVault images

## Removing an Application
You can delete an application using this command:
```
$appid = 2133445
Remove-AGMApplication $appid
```
[Back to top](#usage-examples)
# Audit

## Exploring the Audit log
We can list events in the audit log with this command, but the resulting output will be very long:
```
Get-AGMAudit
```
We need to use [filters](README.md/#filtering) and limits.  You can list all filterable fields with this command:
```
Get-AGMAudit -o
```
In this example we filter on issue date, user name as  well as use a limit:
```
Get-AGMAudit -filtervalue "username=apiuser@iam.gserviceaccount.com&issuedate>2022-11-18" -limit 15
```
## Finding the last command a user issued

While the audit log contains a lot of events where users look at data (get) we may want to see commands where users changed things (post, put and delete).  So if we know the username we can use this command which looks at posts by default:
```
Get-AGMLibLastPostCommand -username apiuser@.iam.gserviceaccount.com
```
Output will typically look like this, where in this example the user expired image 425577
```
@type      : auditRest
id         : 986486
href       : https://agm.backupdr.actifiogo.com/actifio/localaudit/986486
issuedate  : 2022-11-16 10:51:39
username   : apiuser@iam.gserviceaccount.com
command    : POST https://agm.backupdr.actifiogo.com/actifio/backup/425577/expire force=TRUE Session 5b53bf3e
ipaddress  : 10.1.1.1
component  : RESTful
status     : 10008
privileged : False
```
We can look for other command types with either:
* ```-delete``` To look for deletes normally associated with deleting things 
* ```-put``` To look for puts, normally associated with changing things
* ```-limit 2``` To get the last 2 commands.   You can look for as many commands as you like.

[Back to top](#usage-examples)
# Backup Plans

A Backup Plan is a combination of a policy template (that defines what backup policies we use, when they are run and how long the resulting backup is retained) and a resource profile (that defines which appliance creates the backup and where it stores it).  We apply a backup plan to an application and backups start to get created.

Note that Backup Plans is the new term for the SLA Architect.  If you see the term Backup Plan, this is the equivalent of what Actifio called an SLA.

## Applying a Backup Plan

When we apply a backup plan (SLA) to an application we are protecting or managing it.  To complete this task we need three things:
* ```-appid xxx```      The Application ID
* ```-sltid yyy```   The Policy template ID
* ```-slpid zzz```   The Resource profile ID

In this example the application name is ```bastion``` so we find the Application ID with this command, confirming the apptype is correct and that it is currently being protected (managed=true):
```
$appname = "bastion"
Get-AGMApplication -filtervalue appname=$appname | select id,appname,apptype,managed
```
The output should look like this:
```
id     appname apptype     managed
--     ------- -------     -------
709575 bastion GCPInstance   False
```
We learn the sltid command with this command:
```
Get-AGMSLT | select id,name
```
The output should look like this:
```
id     name
--     ----
425079 VMware Direct to OnVault
425013 VMware Snap to OnVault
108758 pd-snaps-multiregional
```
We now learn the slpid with this command:
```
Get-AGMSLP  | select id,name,localnode
```
The output should look like this:
```
id     name                       localnode
--     ----                       ---------
706611 backup-server29736_Profile backup-server-29736
406229 29736 avwarglab            backup-server-29736
```
We now assemble the command we need to use.  Note that if you wanted to change any policy settings you should add ```-scheduler disabled``` to the command:
```
$appid = 709575
$sltid = 108758
$slpid = 706611
New-AGMSLA -appid $appid -sltid $sltid -slpid $slpid 
```    
The command should return SLA information.

We can validate our policy is applied with a command like this:
```
(Get-AGMApplication $appid).sla
```
## Disabling a Backup Plan
We can disable the SLA for a particular application or logical group or literally every known application.  This command is interactive:
```
Set-AGMLibSLA
```
It will build a command you can run then or store for later.  A typical command would look like this:
```
Set-AGMLibSLA -slaid 741509  -scheduler enable -expiration enable
```

## Backup Plan Enablement Status
Each backup plan can have its scheduler disabled (to prevent new backups being created) as well as its expiration disabled (to prevent old backups being expired).  To check on all applications you this command:
```
Get-AGMLibSLA 
```
Output will look like this:
```
hostname     appname                apptype         slaid  appid  scheduler expiration sltname                  slpname                    logicalgroupname
--------     -------                -------         -----  -----  --------- ---------- -------                  -------                    ----------------
avw tiny     AVW Tiny               VMBackup        741509 409016 enabled   enabled    VMware Direct to OnVault 29736 avwargolis
bastion      bastion                GCPInstance     965514 709575 enabled   enabled    pd-snaps-multiregional   backup-server29736_Profile
```
You can also specify the following things to see a subset:
* ```-appid 409016``` To see a specific appid, in this example appid 409016
* ```-slaid 741509``` To see a specific sla (Backup plan) ID, in this example slaid 741509
* ```-logicalgroup 1234``` To see all members of a specific logical group, in this example group ID 1234

## Backup Plan Policy Usage

If you wish to display general information about the policies in your backup plan templates then use this command:
```
Get-AGMLibPolicies
```
If you wish to know which policies are using enforced retention use this command:
```
Get-AGMLibPolicies -enforcedretention
```
If you wish to know where your Compute Engine instance snapshots are going use this command:
```
Get-AGMLibPolicies -snapshotlocation
```
If you wish to display all advanced policy options use this command:
```
Get-AGMLibPolicies -advancedpolicysettings
```

## Backup Plan Policy Usage By Application

If you wish to know exact details about what policies are applied to a specific application then learn the application ID using the procedure [here](#application-ids) and then run this command (using your AppID):
```
$appid=789632
Get-AGMLibAppPolicies -appid $appid
```
Output should look like this:
```
policyid  : 70801
name      : Daily DB
operation : snapshot
priority  : medium
retention : 7 days
starttime : 00:00
endtime   : 07:00
rpo       : 24 hours

policyid  : 105138
name      : Daily OV
operation : onvault
priority  : medium
retention : 30 days
starttime : 00:00
endtime   : 18:50
rpo       : 24 hours
```

## Backup Plan Removal

To remove a backup plan (SLA) from an application (to unprotect or unmanage it), we need the application ID.  In this example the application name is ```bastion``` so we find the Application ID with this command, confirming the apptype is correct and that it is currently being protected (managed=true):
```
$appname = "bastion"
Get-AGMApplication -filtervalue appname=$appname | select id,appname,apptype,managed
```
The output should look like this:
```
id     appname apptype     managed
--     ------- -------     -------
709575 bastion GCPInstance    True
```
We then take the appid and remove the backup plan (SLA):
```
$appid=709575
Remove-AGMSLA -appid $appid
```
We then confirm managed is now false, confirming the application is no longer protected:
```
Get-AGMApplication -filtervalue appname=bastion | select id,appname,apptype,managed

id     appname apptype     managed
--     ------- -------     -------
709575 bastion GCPInstance   False
```
## Backup Plan Removal In Bulk

In this scenario, a large number of VMs that were no longer required were removed from the vCenter. However, as those VMs were still being managed at the time of removal from the VCenter, the following error message is being received constantly
 
 ```
Error 933 - Failed to find VM with matching BIOS UUID
```

### 1)  Create a list of affected VMs

First we need to create a list of affected VMs.  The simplest way to do this is to run these commands:

There are two parameters in the filtervalue.
The first is the errorcode of 933
The second is the startdate.  You need to update this.

This is the command we thus run (connect-agm logs us into the appliance).
We grab just the Appname  (which is the VMname) and AppID of each affected VM and reduce to a unique list in a CSV file

```
Get-AGMJobHistory -filtervalue "errorcode=933&startdate>2020-09-01"  | select appname,appid | sort-object appname | Get-Unique -asstring | Export-Csv -Path .\missingvms.csv -NoTypeInformation
```
### 2). Edit your list if needed

Now open your CSV file called missingvms.csv and go to the VMware administrator.
Validate each VM is truly gone.
Edit the CSV and remove any VMs you don't want to unprotect.   
 
### 3) Unprotection script

Because we have a CSV file of affected VMs we can run this simple PowerShell script. 

Import the list and validate the import worked by displaying the imported variable.  In this example we have only four apps.
```
$appstounmanage = Import-Csv -Path .\missingvms.csv
$appstounmanage
```
Output should look like this:
```
appname      appid
-------      --
duoldapproxy 655601
SYDWINDC1    655615
SYDWINDC2    6227957
SYDWINFS2    5370126
```
Then paste this script to validate each app has an SLA ID
```
foreach ($app in $appstounmanage)
{ $slaid = get-agmSLA -filtervalue appid=$($app.appid)
write-host "Appid $($app.appid) has SLA ID $($slaid.id)" }
```
Output will be similar to this:
```
Appid 655601 has SLA ID 6749490
Appid 655615 has SLA ID 6749492
Appid 6227957 has SLA ID 6749494
Appid 5370126 has SLA ID 6749496
```
If you want to build a backout plan, run this script now:
```
foreach ($app in $appstounmanage)
{ $slaid = Get-AGMSLA -filtervalue appid=$($app.appid)
$slpid =  $slaid.slp.id
$sltid =  $slaid.slt.id
write-host "New-AGMSLA -appid $($app.appid) -slpid $slpid -sltid $sltid" }
```
It will produce a list of commands to re-protect all the apps.
You would simply paste this list into your Powershell session:
```
New-AGMSLA -appid 655601 -slpid 655697 -sltid 4171
New-AGMSLA -appid 655615 -slpid 655697 -sltid 4181
New-AGMSLA -appid 6227957 -slpid 655697 -sltid 4171
New-AGMSLA -appid 5370126 -slpid 655697 -sltid 4181
```
Now we are ready for the final step.  Run this script to unprotect the VMs:
```
foreach ($app in $appstounmanage)
{ Remove-AGMSLA -appid $($app.appid) }
```
Output will be blank but the VMs will all be unprotected

### 4) Bulk deletion of the Applications

If any of the Applications have images, it is not recommended you delete them, as this creates orphans apps and images.
If you are determined to also delete them, run this script to delete the VMs from the backup software.
```
foreach ($app in $appstounmanage)
{ Remove-AGMApplication -appid $($app.appid) }
```
Output will be blank but the VMs will all be deleted.



## Importing and Exporting Policy Templates

In this user story we are going to export our Policy Templates (also called Service Level Templates or SLTs) from our AGM/Management Console in case we want to import them into a different one.

First we validate our SLTs.

```
Get-AGMSLT | select id,name

id    name
--    ----
25606 FSSnaps_RW_OV
17796 FSSnaps
6523  Snap2OV
6392  PDSnaps
```
We now export all the SLTs to a file called export.json.  If we only want to export specific SLTs, then don't specify **-all** and you will get a help menu.
```
Export-AGMLibSLT -all -filename export.json
```
We now login to our target AGM/Management Console.

We validate there are no Templates.   Currently this function expects there to be no templates in the target.  However if there are, as long as there are no name clashes, the import will still succeed.  In this example there are no templates in the target.
```
Get-AGMSLT
```
Output should look like this:
```
count items
----- -----
    0 {}
```
We now import the Templates and then validate we now have four imported SLTs:
```
Import-AGMLibSLT -filename export.json
```
Output should look like this:
```
count items
----- -----
    4 {@{@type=sltRest; id=21067; href=https://10.194.0.3/actifio/slt/21067; name=FSSnaps_RW_OV; override=true; policy_href=https://10.194.0.3/actifio/slt/21067/policy}, @{@type=sltRest; id=21070; href=https://10.194.0.3/acti…
```
We check what happened:
```
Get-AGMSLT | select id,name
```
Output should look like this:
```
id    name
--    ----
21081 PDSnaps
21072 Snap2OV
21070 FSSnaps
21067 FSSnaps_RW_OV
```
Our import is now complete.

[Back to top](#usage-examples)
# Billing

Billing should be tracked in the relevant billing page of the Cloud Console.  This section is to help you understand what generated those bills.

# Backup SKU Usage

Usage for the Backup and DR Service is charged on a per GiB of protected application (front end) data.    Pricing is documented here:
https://cloud.google.com/backup-disaster-recovery/pricing

If you wish to display how large your applications are in GiB per SKU type (to help allocate Backup SKU usage between business departments or just to understand how large an application is), then you can use the following command:
```
Get-AGMLibBackupSKUUsage
```
Output will look like this:
```
Get-AGMLibBackupSKUUsage

appliancename  : backup-server-29736
applianceid    : 406219
apptype        : VMBackup
hostname       : avw tiny
appname        : AVW Tiny
skudescription : Default Backup SKU for VM (Compute Engine and VMware) and File system data
skuusageGiB    : 4.051
```
If the SKU description is not listed then please open an Issue in GitHub and share the listed apptype.

[Back to top](#usage-examples)

# Compute Engine Instances

Compute Engine Instances and their backups are called different things depending on where you look:

* GCE Instances - These are Compute Engine Instances
* GCP Instances - These are Compute Engine Instances
* PD Snapshots - These are backups of snapshots of the persistent disks used by Compute Engine Instances

## Compute Engine Cloud Credentials

Cloud Credentials point to stored credentials for the Service Account that is used to create Compute Engine instance backups and then use them.   

Changes with release 11.0.2 and higher:

* If your Appliances were installed with version 11.0.2 or higher then each appliance will have an auto-created cloud credential that does not need JSON keys.   This means there is no need to ever run the ```New-AGMCredential``` function.   Simply use the default credential and in Cloud IAM add add the relevant appliance service account to the relevant projects with the ```Backup and DR Compure Engine Operator``` role.   If you still wish to manually add cloud credentials then the syntax needs to be modified.
* If your Appliances were installed version 11.0.1 or lower and have been upgraded to 11.0.2 or higher, then follow the procedure [here](https://cloud.google.com/backup-disaster-recovery/docs/configuration/create-cloud-credentials#replace_a_json_key_cloud_credential_with_an_appliance_service_account_credential) to covert to a *JSON-less* cloud credential.

### Listing Cloud Credentials

Use the following command:
```
Get-AGMCredential
```
Output should look like this in release 11.0.1 and below:
```
@type          : cloudCredentialRest
id             : 218150
href           : https://10.152.0.5/actifio/cloudcredential
sources        : {@{srcid=20740; clusterid=145759989824; appliance=; name=london; cloudtype=GCP; region=europe-west2-b; projectid=avwlab2; serviceaccount=avwlabowner@avwlab2.iam.gserviceaccount.com}}
name           : london
cloudtype      : GCP
region         : europe-west2-b
projectid      : avwlab2
serviceaccount : avwlabowner@avwlab2.iam.gserviceaccount.com
```
Output should look like this in release 11.0.2 and above.  The cket difference is the ```usedefaultsa``` field will tell you if this is a *json-less* credential.
```
@type          : cloudCredentialRest
id             : 1430329
href           : https://agm-249843756318.backupdr.actifiogo.com/actifio/cloudcredential
clusterid      : 145666187717
sources        : {@{srcid=8960; clusterid=145666187717; appliance=; name=cred1; cloudtype=GCP;
                 region=australia-southeast1-c; projectid=avwarglab1;
                 serviceaccount=melbourne-82270@avwarglab1.iam.gserviceaccount.com; vaultpool=; vault_udsuid=0}}
name           : cred1
cloudtype      : GCP
region         : australia-southeast1-c
projectid      : avwarglab1
serviceaccount : melbourne-82270@avwarglab1.iam.gserviceaccount.com
vault_udsuid   : 1196377951
usedefaultsa   : True
immutable      : False
```

### Creating new cloud credential (11.0.1 or lower):

When working with appliances on release 11.0.1 or lower, use syntax like this where you specify the file name of the JSON and comma separate the cluster IDs:
```
New-AGMCredential -name test -filename ./glabco-4b72ba3d6a69.json -zone australia-southeast1-c -clusterid "144292692833,145759989824"
```
Output should look like this:
```
@type          : cloudCredentialRest
id             : 219764
href           : https://10.152.0.5/actifio/cloudcredential
sources        : {@{srcid=214315; clusterid=144292692833; appliance=; name=test; cloudtype=GCP; region=australia-southeast1-c; projectid=glabco; serviceaccount=avw-gcsops@glabco.iam.gserviceaccount.com}, @{srcid=21546;
                 clusterid=145759989824; appliance=; name=test; cloudtype=GCP; region=australia-southeast1-c; projectid=glabco; serviceaccount=avw-gcsops@glabco.iam.gserviceaccount.com}}
name           : test
cloudtype      : GCP
region         : australia-southeast1-c
projectid      : glabco
serviceaccount : avw-gcsops@glabco.iam.gserviceaccount.com
```

Situation where key cannot manage project
```
New-AGMCredential -name test -filename ./glabco-4b72ba3d6a69.json -zone australia-southeast1-c -clusterid "144292692833,145759989824" -projectid glabco1

@type                    errors
-----                    ------
testCredentialResultRest {@{errorcode=4000; errormsg=No privileges for project or incorrect project id provided in credential json.; clusters=System.Object[]}}
```
Duplicate name
```
New-AGMCredential -name test -filename ./glabco-4b72ba3d6a69.json -zone australia-southeast1-c -clusterid "144292692833,145759989824"

err_code err_message
-------- -----------
   10023 Create cloud credential failed on appliance avwlab2sky error code 10006 message Unique cloud credential name required: test,Create cloud credential failed on appliance londonsky.c.avwlab2.internal error code 10006 message U…
```

### Creating new cloud credential (11.0.2 or higher):

When working with appliances on release 11.0.2 or higher, use syntax like this where you specify the OnVault pool ID with ```udsuid```  Note that:

* You do not need to specify the project ID
* You can only specify one appliance ID (each credential is unique to an appliance)
* If you do not specify an OnVault Pool you will need to provide one using the udsuid which you can learn with this command:
```Get-AGMDiskPool -filtervalue pooltype=vault | select-object name,udsuid,@{N='appliancename'; E={$_.cluster.name}},@{N='applianceid'; E={$_.cluster.clusterid}}```

Here is an example of working syntax:
```
New-AGMCredential -applianceid 145666187717 -zone "australia-southeast1-b" -udsuid "1196377951" -name test6
```
Output should look like this:
```
@type          : cloudCredentialRest
id             : 1425434
href           : https://agm-249843756318.backupdr.actifiogo.com/actifio/cloudcredential
clusterid      : 145666187717
sources        : {@{srcid=6627; clusterid=145666187717; appliance=; name=test6; cloudtype=GCP; region=australia-southeast1-b; projectid=avwarglab1;
                 serviceaccount=melbourne-82270@avwarglab1.iam.gserviceaccount.com; vaultpool=; vault_udsuid=0}}
name           : test6
cloudtype      : GCP
region         : australia-southeast1-b
projectid      : avwarglab1
serviceaccount : melbourne-82270@avwarglab1.iam.gserviceaccount.com
vault_udsuid   : 1196377951
usedefaultsa   : True
immutable      : False
```

### Updating an existing cloud credential

The most common reason for doing this is to update the JSON key.  Use syntax like this where we specify the credential ID and the filename of the JSON file.
```
Set-AGMCredential -credentialid 1234 -filename keyfile.json
```
You can also use this command to update the default zone or the credential name as well.   However zone, name and clusterid are not mandatory and only need to be supplied if you are changing them.   The clusterid parameter would determine which appliances get updated, by default all relevant appliances are updated.   You can learn the credential ID with **Get-AGMCredential** and the clusterid will be in the sources field of the same output.   

### Deleting a Cloud Credential
```
Remove-AGMCredential -credentialid 219764 -applianceid "145759989824,144292692833"
```
Update existing credential with new key and change its name
```
Set-AGMCredential -id 219764  -name test1 -filename ./glabco-4b72ba3d6a69.json
```
Output should look like this:
```
@type          : cloudCredentialRest
id             : 219764
href           : https://10.152.0.5/actifio/cloudcredential
sources        : {@{srcid=214315; clusterid=144292692833; appliance=; name=test1; cloudtype=GCP; region=australia-southeast1-c; projectid=glabco; serviceaccount=avw-gcsops@glabco.iam.gserviceaccount.com}, @{srcid=21546;
                 clusterid=145759989824; appliance=; name=test1; cloudtype=GCP; region=australia-southeast1-c; projectid=glabco; serviceaccount=avw-gcsops@glabco.iam.gserviceaccount.com}}
name           : test1
cloudtype      : GCP
region         : australia-southeast1-c
projectid      : glabco
serviceaccount : avw-gcsops@glabco.iam.gserviceaccount.com
```

## Compute Engine Instance Discovery

### Listing new Compute Engine Instances. 

To learn what Compute Engine VMs are available for discovery, in that they exist in Compute Engine but are not known to Backup and DR.

We search by project and zone and by default this command only shows up to 50 **new** VMs:
```
Get-AGMCloudVM -credentialid 35548 -clusterid 144292692833 -projectid "avwlab2" -zone "australia-southeast1-c"
```
You can set filters to display different discovery status. Can be New, Ignored, Managed or Unmanaged  
For example to list discovered but unmanaged VMs:
```
Get-AGMCloudVM -credentialid 35548 -clusterid 144292692833 -projectid "avwlab2" -zone "australia-southeast1-c" -filter Unmanaged
```
Learn the credential ID with:
```
Get-AGMCredential
```
Learn the cluster ID with:
```
Get-AGMAppliance
```
To learn instance IDs use these two commands:
```
$discovery = Get-AGMCloudVM -credentialid 35548 -clusterid 144292692833 -projectid "avwlab2" -zone "australia-southeast1-c" -filter NEW
$discovery.items.vm | select vmname,instanceid
```
For example:
```
$discovery.items.vm | select vmname,instanceid
```
Output should look like this:
```
vmname      instanceid
------      ----------
consoletest 4240202854121875692
agm         6655459695622225630
```
The total number of VMs that were found and the total number fetched will be different.  In this example, 57 VMs can be found, but only 50 were fetched as the limit defaults to 50:
```
Get-AGMCloudVM -credentialid 35548 -clusterid 144292692833 -projectid avwlab2
```
Output should look like this:
```
count items                             totalcount
----- -----                             ----------
   50 {@{vm=}, @{vm=}, @{vm=}, @{vm=}…}         57
```
By setting the limit to 60 we now fetch all 57 VMs:
```
Get-AGMCloudVM -credentialid 35548 -clusterid 144292692833 -projectid avwlab2 -limit 60
```
Output should look like this:
```
count items                             totalcount
----- -----                             ----------
   57 {@{vm=}, @{vm=}, @{vm=}, @{vm=}…}         57

```

Or we could fetch the first 50 in one command and then in a second command, set an offset of 1, which will fetch all VMs from 51 onwards (offset it added to limit to denote the starting point).  In this example we fetch the remaining 7 VMs (since the limit is 50):
```
Get-AGMCloudVM -credentialid 35548 -clusterid 144292692833 -projectid avwlab2 -limit 50 -offset 1
```
Output should look like this:
```
count items                             totalcount
----- -----                             ----------
    7 {@{vm=}, @{vm=}, @{vm=}, @{vm=}…}         57

```

### Add new Compute Engine Instance

Learn the instanceid and then use this command (comma separate the instance IDs):
```
New-AGMCloudVM -credentialid 35548 -clusterid 144292692833 -projectid "avwlab2" -zone "australia-southeast1-c" -instanceid "4240202854121875692,6655459695622225630"
```

## Compute Engine Instance Management

### How to learn if a Compute Engine Instance is being backed up or not.

Use this command:
```
Get-AGMApplication -filtervalue appname=bastion
```
The term we look for is “Managed” = True 
```
Get-AGMApplication -filtervalue apptype=GCPInstance | select appname,apptype,managed,id, @{N='sltid'; E={$_.sla.slt.id}}, @{N='slpid'; E={$_.sla.slp.id}} | ft
```
Output should look like this:
```
appname     apptype     managed id     sltid slpid
-------     -------     ------- --     ----- -----
consoletest GCPInstance   False 224079
bastion     GCPInstance    True 209913 6392  35557
```

### How to apply backup to unmanaged Compute Engine Instance

Use a command like this.   
```
New-AGMSLA -appid 209913 -sltid 6392 -slpid 35557 -scheduler enabled
```

We need to know the App ID (ID from the Get-AGMApplication), SLT and SLP ID.
We can learn the SLT and SLP from existing app, or with:
```
Get-AGMSLT
Get-AGMSLP
```

### How to learn the IP address of a Compute Engine Instance

If we know the name of the Compute Engine VM, then use this command: 
```
Get-AGMApplication -filtervalue appname=bastion
```
Here is an example:
```
$appdata = Get-AGMApplication -filtervalue appname=bastion
$appdata.host.ipaddress
10.152.0.3

```

## Compute Engine Instance Conversion from VMware VM

In this user story we are going to use VMware VM snapshots to create a new Compute Engine Instance.  This will be done by using the **New-AGMLibGCEConversion** command.

This command requires several inputs so first we explore how to get them.

### Creating a single Compute Engine Instance Instance from VMware Backup

The best way to create the syntax for this command, at least for the first time you run it,  is to simply run the **New-AGMLibGCEConversion** command without any parameters.
This starts what we called *guided mode* which will help you learn all the syntax to run the command.
The guided menus will ask questions in roughly the same order as the menus appear in the Web GUI.
The end result is you will get several choices:

1. Run the command there and then
1. Print out a simple command to run later.   Note you may want to edit this command as we explain in a moment.
1. Print out a sample CSV file to use with  **New-AGMLibGCEConversionMulti**

#### Determining which image is used for the mount

The sample command printed by guidedmode has an imageid, an appid and an appname. Consider:
```
-appid       If you specify this, then the most recent image for that app will be mounted.  This is the most exact choice to get the latest image.
-appname     If you specify this, then the most recent image for that app will be mounted provided the appname is unique.   If the appname is not unique, then you will need to switch to appid.
-imageid     If you specify this, then this image will be mounted. You will need to learn this imageid before you run the command.
-imagename   If you specify this, then this image will be mounted. You will need to learn this imagename before you run the command.
```
In general the best choice is **-appid** as it saves you having to work out the imageid or name and gives you the most recent image (for the latest RPO).
If constructing a CSV file for multi mount you always need to include the **appname**, even if you are using the **appid**.  This is to ensure we can identify the source app.

#### Manually constructing output

If you want to manually construct the output, or get some variables to tweak the output consider the following tips:

To learn which Cloud Credential srcids are available use the following command.  Note that this is appliance specific, so when you specify a srcid you are specifing a service account that is stored on a specific appliance.  This means if you want to split the workload across multiple appliances, then you can do this by using the relevant srcid of each appliance (although this also need the relevant applications to be imported into the relative appliances when using OnVault backups).
```
Get-AGMLibCredentialSrcID
```
To learn the AppIDs use this command (note the ApplianceName is where the images were created, in other words the source appliance, not the one running the mount):
```
Get-AGMApplication -filtervalue "apptype=SystemState&apptype=VMBackup" | select id,appname,@{N='appliancename'; E={$_.cluster.name}} | sort-object appname
```
To learn the image ID or image name, you could use this command (change jobclass to snapshot or StreamSnap if needed):
```
Get-AGMImage -filtervalue "apptype=SystemState&apptype=VMBackup&jobclass=OnVault" | select appname,id,name,consistencydate,@{N='diskpoolname'; E={$_.diskpool.name}} | sort-object appname,consistencydate | format-table
```

There are many parameters that may need to be supplied:
```
-appid           The application ID of the source VMWare VM you want to mount.  If you use this you don't need to specify an image ID or imagename.   It will use the latest image of that application.
-appname         The application name of the source VMWare VM you want to mount.  This needs to be unique.  If you use this you don't need to specify an image ID or imagename.   It will use the latest image of that application.
-imageid         You need to supply either the imageid or the imagename or both (or specify -appid instead to get the latest image).  To avoid using this, you can specify -appid or -appname instead
-imagename       You need to supply either the imageid or the imagename or both (or specify -appid instead to get the latest image).  To avoid using this, you can specify -appid or -appname instead
-srcid           Learn this with Get-AGMLibCredentialSrcID.  You need to use the correct srcid that matches the appliance that is going to run the mount.
-serviceaccount  The service account.
-projectname     This is the unique Google Project name where the new instance will be created.
-sharedvpcprojectid  If the instance is being created in a service project, what is the ID the project that is sharing the VPC (optional)
-nodegroup       If creating an instance into a sole tenant node group, this is the name of the node group (optional)
-region          This is the Google Cloud Region such as:   australia-southeast1
-zone            This is the Google Cloud Zone such as: australia-southeast1-c
-instancename    This is the name of the new instance that will be created.   It needs to be unique in that project
-machinetype     This is the Google Cloud instance machine type such as:  e2-micro
-networktags     Comma separate as many tags as you have, for instance:   -networktags "http-server,https-server"   
-labels          Labels are key value pairs.   Separate key and value with colons and each label with commas.   For example:   -labels "pet:cat,food:fish"
-nic0network     The network name in URL format for nic0
-nic0subnet      The subnet name in URL format for nic0
-nic0externalip  Only 'none' and 'auto' are valid choices.  If you don't use this variable then the default for nic0 is 'none'
-nic0internalip  Only specify this is you want to set an internal IP.  Otherwise the IP for nic0 will be auto assigned.   
-poweroffvm      By default the new Compute Engine Instance will be left powered on after creation.   If you want it to be created but then powered off, then specify this flag.
-migratevm       By default the new Compute Engine Instance will be dependent on the mounting Appliance.  To migrate all data onto Compute Engine Persistent Disk, then specify this flag.
-preferedsource  Optional,  used if we want to force selection of images from a particular storage pool, either snapshot, streamsnap or onvault  (use lower case)
```
Optionally you can request a second NIC using nic1:
```
-nic1network     The network name in URL format for nic1
-nic1subnet      The subnet name in URL format for nic1
-nic1externalip  Only 'none' and 'auto' are valid choices.  If you don't use this variable then the default for nic1 is 'none'
-nic1internalip  Only specify this is you want to set an internal IP.  Otherwise the IP for nic1 will be auto assigned.   
```
Optionally you can specify that all disks be a different type:
```
-disktype        Has to be one  of pd-balanced, pd-extreme, pd-ssd, pd-standard   All disks in the instance will use this disk type
```
This bring us to command like this one:
```
New-AGMLibGCEConversion -imageid 56410933 -srcid 1234 -region australia-southeast1 -zone australia-southeast1-c -projectname myproject -instancename avtest21 -machinetype e2-micro -networktags "http-server,https-server" -labels "dog:cat,sheep:cow" -nic0network "https://www.googleapis.com/compute/v1/projects/projectname/global/networks/default" -nic0subnet "https://www.googleapis.com/compute/v1/projects/projectname/regions/australia-southeast1/subnetworks/default" -nic0externalip auto -nic0internalip "10.152.0.200" -poweroffvm 
```

What is not supported right now:
1)  Specifying more than one internal IP per subnet.
2)  Specifying different disk types per disk

If you get timeouts, then increase the timeout value with **-timeout 600** when running connect-agm


## Compute Engine Instance Multi Conversion from VMware VM

The expected configuration in this scenario is that the end-user will be looking to recover workloads from VMware into a Google Cloud Zone

| Production Site  | DR Site |
| ------------- | ------------- |
| VMware | Google Cloud Zone |

The goal is to offer a simplified way to manage failover from Production to DR where:
* The backup mechanism is to use VMware snapshots
* These images are created by an on-premises Backup Appliance and then replicated into cloud either in an OnVault pool or via StreamSnap.
* DR occurs by issuing commands to the DR Appliance to create new Compute Engine Instance Instances (most likely after importing the OnVault images)
* You may need to first run an OnVault import using this [method](#image-import-from-onvault)

The best way to create the syntax for this command, at least for the first time you run it,  simply run the **New-AGMLibGCEConversion** command without any parameters.
This starts what we called *guided mode* which will help you create the command.
The guided menus will appear in roughly the same order as the menus appear in the Web GUI.
The end result is you wil get two choices:

1. Print out a simple command
1. Print out a sample CSV file to use with  **New-AGMLibGCEConversionMulti**

If you want to manually construct the output, or get some variables to tweak the output consider the following tips:


### VMware to Compute Engine Instance CSV file

We can take the **New-AGMLibGCEConversion** command to create a new Compute Engine VM and store the parameters needed to run that command in a CSV file. 

If the applications are not yet imported you can use the appname  field provided the VMnames are unique.
Here is an example of the CSV file:
```
srcid,appid,appname,projectname,sharedvpcprojectid,region,zone,instancename,machinetype,serviceaccount,nodegroup,networktags,poweroffvm,migratevm,labels,preferedsource,disktype,nic0network,nic0subnet,nic0externalip,nic0internalip,nic1network,nic1subnet,nic1externalip,nic1internalip
391360,296433,"Centos2","project1","hostproject1","europe-west2","europe-west2-a","newvm1","n1-standard-2","systemstaterecovery@project1.iam.gserviceaccount.com","nodegroup1","https-server",False,True,status:failover,onvault,pd-standard,https://www.googleapis.com/compute/v1/projects/project1/global/networks/actifioanz,https://www.googleapis.com/compute/v1/projects/project1/regions/europe-west2/subnetworks/default,auto,,https://www.googleapis.com/compute/v1/projects/project1/global/networks/default,https://www.googleapis.com/compute/v1/projects/project1/regions/europe-west2/subnetworks/default,,  
       
```
The main thing is the headers in the CSV file needs to be exactly as shown as they are the parameters we pass to the command (although the order is not important).
We can then run a command like this specifying our CSV file:
```
New-AGMLibGCEConversionMulti -instancelist recoverylist.csv 
```
This will load the contents of the file **recoverylist.csv** and use it to start multiple **New-AGMLibGCEConversion** jobs.   They will run in parallel but be started serially.

What is not supported right now:

1.  Specifying more than one internal IP per subnet.
1.  Specifying different disk types per disk
1.  More than two NICS per instance

#### Monitoring the jobs created by a multi mount by creating an object

When you run a multimount, by default all jobs will run before any output is printed.   What we output is a nicely formatted object listing each line in the CSV, the app details, the command that was run and the results.  

The best way to manage this is to load this output into your own object, so do something like this:
```
$newrun = New-AGMLibGCEConversionMulti -instancelist april12test1.csv
```
Then display the output like this:
```
$newrun

appname : Centos3
appid   :
result  : started
message : Job_0866903Optional[Job_0866903] to mount londonsky.c.project1.internal_Image_0499948 started
command : New-AGMLibGCEConversion -projectname project1 -machinetype n1-standard-2 -instancename "apr12test1centos3" -nic0network "https://www.googleapis.com/compute/v1/projects/project1/global/networks/actifioanz" -nic0subnet "https://www.googleapis.com/compute/v1/projects/project1/regions/australia-southeast1/subnetworks/australia" -region "australia-southeast1" -zone "australia-southeast1-a" -srcid
          "391360" -appname "Centos3" -serviceaccount "systemstaterecovery@project1.iam.gserviceaccount.com" -preferedsource onvault

appname : centos2
appid   :
result  : failed
message : Failed to resolve centos2 to a unique valid VMBackup app.  Use Get-AGMLibApplicationID and try again specifying -appid
command : New-AGMLibGCEConversion -projectname project1 -machinetype n1-standard-2 -instancename "apr12test1centos2" -nic0network "https://www.googleapis.com/compute/v1/projects/project1/global/networks/actifioanz" -nic0subnet "https://www.googleapis.com/compute/v1/projects/project1/regions/australia-southeast1/subnetworks/australia" -region "australia-southeast1" -zone "australia-southeast1-a" -srcid
          "391360" -appname "centos2" -serviceaccount "systemstaterecovery@project1.iam.gserviceaccount.com" -preferedsource onvault
```
You can then find all the jobs that didn't start like this:
```
$newrun | where-object {$_.result -ne "started"}

appname : centos2
appid   :
result  : failed
message : Failed to resolve centos2 to a unique valid VMBackup app.  Use Get-AGMLibApplicationID and try again specifying -appid
command : New-AGMLibGCEConversion -projectname project1 -machinetype n1-standard-2 -instancename "apr12test1centos2" -nic0network "https://www.googleapis.com/compute/v1/projects/project1/global/networks/actifioanz" -nic0subnet "https://www.googleapis.com/compute/v1/projects/project1/regions/australia-southeast1/subnetworks/australia" -region "australia-southeast1" -zone "australia-southeast1-a" -srcid
          "391360" -appname "centos2" -serviceaccount "systemstaterecovery@project1.iam.gserviceaccount.com" -preferedsource onvault
```
Once you understand the error you can manually learn the command like this, so you can edit it and run it manually:
```
($newrun | where-object {$_.result -ne "started"}).command
```

#### Monitoring the jobs created by a multi mount by creating an object
If you want to just see the output as each job is run, then add **-textoutput**

```
New-AGMLibGCEConversionMulti -instancelist april12test1.csv -textoutput
```
Output should look like this:
```
The following command encountered this error:       Instance Name already in use
New-AGMLibGCEConversion -projectname project1 -machinetype n1-standard-2 -instancename "apr12test1centos1" -nic0network "https://www.googleapis.com/compute/v1/projects/project1/global/networks/actifioanz" -nic0subnet "https://www.googleapis.com/compute/v1/projects/project1/regions/australia-southeast1/subnetworks/australia" -region "australia-southeast1" -zone "australia-southeast1-a" -srcid "391360" -appname "Centos1" -serviceaccount "systemstaterecovery@project1.iam.gserviceaccount.com" -preferedsource onvault

The following command started this job:  Job_0867154Optional[Job_0867154] to mount londonsky.c.project1.internal_Image_0499948 started
New-AGMLibGCEConversion -projectname project1 -machinetype n1-standard-2 -instancename "apr12test1centos3" -nic0network "https://www.googleapis.com/compute/v1/projects/project1/global/networks/actifioanz" -nic0subnet "https://www.googleapis.com/compute/v1/projects/project1/regions/australia-southeast1/subnetworks/australia" -region "australia-southeast1" -zone "australia-southeast1-a" -srcid "391360" -appname "Centos3" -serviceaccount "systemstaterecovery@project1.iam.gserviceaccount.com" -preferedsource onvault
```

### Managing the mounted Compute Engine Instance Instance 

Once we have created a new Compute Engine Instance from PD snapshot, there is no dependency on the appliance because the disks for the instance are all Persistent Disks rather than shared disks from an appliance Storage Pool,  but the mount is still shown as an Active Image, which means it needs to be managed.   We can see the Active Images with this command:
```
Get-AGMLibActiveImage
```
Output should look like this:
```
imagename        : Image_0021181
apptype          : GCPInstance
appliancename    : project1sky
hostname         : windows
appname          : windows
mountedhost      : avrecovery4
allowedip        :
childappname     : avrecovery4
consumedsize_gib : 0
daysold          : 0
label            :
imagestate       : Mounted
```
We have two choices on how to handle this image:

1. Unmount and delete. This command deletes the mounted image record on the appliance side and the Compute Engine Instance on the Google Cloud side.

```
 Remove-AGMMount Image_0021181  -d
```
2. Preserve the image on Google Cloud side. This command deletes the mounted image record on the appliance side but leaves the Compute Engine Instance on the Google Cloud side. In the Web GUI this is called forgetting the image.   You can see the only difference with the choice above is the -p for preserve.
```
 Remove-AGMMount Image_0021181  -d -p
```
## Compute Engine Instance Mount

In this user story we are going to use Persistent Disk Snapshots to create a new Compute Engine Instance.  This will be done by using the following command:   **New-AGMLibGCPInstance**

This command requires several inputs so first we explore how to get them.

### Demo video

This video will help you understand how to use this command:   https://youtu.be/hh1seRvRZos

### Creating a single Compute Engine Instance from Snapshot

The best way to create the syntax for this command, at least for the first time you run it,  is to simply run the **New-AGMLibGCPInstance** command without any parameters.
This starts what we called *guided mode* which will help you learn all the syntax to run the command.
The guided menus will appear in roughly the same order as the menus appear in the Web GUI.
The end result is you will get several choices:

1. Run the command
1. Print out a simple command to run later.   Note you may want to edit this command as we explain in the next section.
1. Print out a sample CSV file to use with  **New-AGMLibGCPInstanceMultiMount**

#### Determining which image is used for the mount

The sample command printed by guidedmode has an imageid, an appid and an appname. Consider:
```
-appid       If you specify this, then the most recent image for that app will be mounted.  This is the most exact choice to get the latest image.
-appname     If you specify this, then the most recent image for that app will be mounted provided the appname is unique.   If the appname is not unique, then you will need to switch to appid.
-imageid     If you specify this, then this image will be mounted. You will need to learn this imageid before you run the command.
-imagename   If you specify this, then this image will be mounted. You will need to learn this imagename before you run the command.
```
In general the best choice is **-appid** as it saves you having to work out the imageid or imagename and gives you the most recent image (for the best RPO), 
If constructing a CSV file for multi mount you always need to specify the appname, even if you are using the appid.  This is to ensure we can identify the source app.

#### Manually constructing output

If you want to manually construct the output, or get some variables to tweak the output, consider the following tips:

To learn which Applications are suitable use this command:
```
Get-AGMApplication -filtervalue "apptype=GCPInstance&managed=True" | select id,appname,@{N='appliancename'; E={$_.cluster.name}}
```
You could use the same command to export to CSV, like this:
```
Get-AGMApplication -filtervalue "apptype=GCPInstance&managed=True" | select id,appname | Export-Csv -Path ./applist.csv
Get-Content ./applist.csv
```

To learn which Cloud Credential srcids are available use this command:
```
Get-AGMLibCredentialSrcID
```
Make sure that the credential is on the same appliance that is managing the application.
To learn the image ID or image name, you could use this command:
```
Get-AGMImage -filtervalue "apptype=GCPInstance&jobclass=snapshot" | select appname,id,name,consistencydate,diskpool | ft
```
There are many parameters that need to be supplied:
```
-appid           The application ID of the source Compute Engine Instance you want to mount.  If you use this you don't need to specify an image ID or name.   It will use the latest snapshot of that application.
-imageid         You need to supply either the imageid or the imagename or both (or specify -appid instead to get the latest image)
-imagename       You need to supply either the imageid or the imagename or both (or specify -appid instead to get the latest image)
-srcid           Learn this with Get-AGMLibCredentialSrcID.   You need to use the correct srcid that matches the appliance that is protecting the application. 
-serviceaccount  The service account that is being used to request the instance creation.  This is optional.  Otherwise it will use the account from the cloud credential (which is the preferred method)
-projectname     This is the unique Google Project name 
-zone            This is the Compute Engine Zone such as: australia-southeast1-c
-instancename    This is the name of the new instance that will be created.   It needs to be unique in that project
-machinetype     This is the Compute Engine instance machine type such as:  e2-micro
-networktags     Comma separate as many tags as you have, for instance:   -networktags "http-server,https-server"   
-labels          Labels are key value pairs.   Separate key and value with colons and each label with commas.   For example:   -labels "pet:cat,drink:milk"
-retainlabel     Specify true and then any labels in the selected image will be retained in the new Compute Engine instance. Partial label retention is not supported.
-nic0hostproject The project ID of the host project.  This is only needed if nic0network is not in URL format and if the target project is a service project
-nic0network     The network name in URL format for nic0
-nic0subnet      The subnet name in URL format for nic0
-nic0externalip  Only 'none' and 'auto' are valid choices.  If you don't use this variable then the default for nic0 is 'none'
-nic0internalip  Only specify this is you want to set an internal IP.  Otherwise the IP for nic0 will be auto assigned.   
-poweronvm       By default the new Compute Engine Instance will be powered on.   If you want it to be created but left powered off, then specify: -poweronvm false
                 There is no need to specify: -poweronvm true 
```
Optionally you can request a second NIC with these parameters:
```
-nic1hostproject The project ID of the host project.  This is only needed if nic0network is not in URL format and if the target project is a service project
-nic1network     The network name in URL format for nic1
-nic1subnet      The subnet name in URL format for nic1
-nic1externalip  Only 'none' and 'auto' are valid choices.  If you don't use this variable then the default for nic1 is 'none'
-nic1internalip  Only specify this is you want to set an internal IP.  Otherwise the IP for nic1 will be auto assigned.  
```
Optionally you can also change the disk type of the disks in the new Compute Engine VM:
```
-disktype        Has to be one of:   pd-balanced, pd-extreme, pd-ssd, pd-standard   All disks in the instance will use this disk type
```
You can specify any labels you want to supply for this new Compute Engine VM with -label, for instance:

 **-label "pet:cat,drink:milk"**

However if you add **-retainlabel true** then any labels that were used the Compute Engine Instance when the snapshot was created will be applied to the new VM.
Lets imagine the original VM had a label:

```bird:parrot```

and we specify the following:   

```-retainlabel true -label "pet:cat,drink:milk"```

then the new VM will have all three labels (the two new ones and the retained one from the original VM).

This brings us to a command like this one:
```
New-AGMLibGCPInstance -imageid 56410933 -srcid 1234 -zone australia-southeast1-c -projectname myproject -instancename avtest21 -machinetype e2-micro -networktags "http-server,https-server" -labels "dog:cat,sheep:cow" -nic0network "default" -nic0subnet "default" -nic0externalip auto -nic0internalip "10.152.0.200" -poweronvm false -retainlabel true
```

## Compute Engine Instance Multi Mount Disaster Recovery

The configuration in this scenario is that you want to recover workloads from one Google Cloud zone into another Google Cloud zone:

| Production Site  | DR Site |
| ------------- | ------------- |
| Google Cloud Zone | Google Cloud Zone |

The goal is to offer a simplified way to manage failover or failback where:
* The backup mechanism is persistent disk snapshots
* The images are created by a Backup Appliance in an alternate zone
* DR occurs by issuing commands to the DR Appliance to create new Compute Engine Instances in the DR zone.

### Demo video

This video will help you understand how to use this command:   

https://youtu.be/hh1seRvRZos

Note this is the same as the video linked in the previous section.

### Compute Engine Instance to Compute Engine Instance CSV file

In this [section](#compute-engine-instance-mount) we show how to use the **New-AGMLibGCPInstance** command to create a new Compute Engine VM.  

* What we can do is store the parameters needed to run that command in a CSV file.  
* We can also generate the CSV file by running **New-AGMLibGCPInstance** in guided mode.
* We then run the **New-AGMLibGCPInstanceMultiMount** command specifying the CSV file.

Here is an example of the CSV file:
```
appid,srcid,projectname,zone,instancename,machinetype,serviceaccount,networktags,labels,nic0hostproject,nic0network,nic0subnet,nic0externalip,nic0internalip,nic1hostproject,nic1network,nic1subnet,nic1externalip,nic1internalip,disktype,poweronvm,retainlabel
35590,28417,prodproject1,australia-southeast1-c,tinym,e2-micro,,"http-server,https-server","dog:cat,sheep:cow",,default,default,,, ,,,,pd-balanced,TRUE,TRUE
51919,28417,prodproject1,australia-southeast1-c,mysqlsourcem,e2-medium,,,,default,default,auto,,,actifioanz,australia,auto,10.186.0.200,,,,
36104,28417,prodproject1,australia-southeast1-c,mysqltargetm,e2-medium,,,,,default,default,,10.152.0.200,,,,,pd-ssd,TRUE,TRUE
```
The main thing is the headers in the CSV file needs to be exactly as shown, as they are the parameters we pass to the command (although the field order is not important).
We can then run a command like this specifying our CSV file:
```
New-AGMLibGCPInstanceMultiMount -instancelist recoverylist.csv
```
This will load the contents of the file recoverylist.csv and use it to run multiple **New-AGMLibGCPInstance** jobs.  The jobs will run in parallel (up to the slot limit). In PowerShell 5 they are started in series, however in PowerShell 7 they are started in parallel in groups of 5 (which you can change with **-limit XX**)
 
If you specify both appid and appname, then the appname column will be ignored.  However having appname is mandatory as it gives you the name of the source application.

What is not supported right now:

1.  Specifying more than one internal IP per subnet.
1.  Specifying different disk types per disk

#### Cleaning up after a multi-mount run

After the multi-mount has finished you may have a large number of Compute Engine Instances to clean up or retain.
One simple strategy is to run this command:
```
Remove-AGMLibMount -gceinstanceforget
```
This will remove the mounted info from the backup side, but leave the instances in place on Google Side.
Then on the Google Console side, keep or delete them as you wish.

#### Monitoring the jobs created by a multi mount by creating an object

When you run a multimount, by default all jobs will run before any output is printed.   What we output is a nicely formatted object listing each line in the CSV, the app details, the command that was run and the results.  

The best way to manage this is to load this output into your own object, so do something like this:
```
$newrun = New-AGMLibGCPInstanceMultiMount -instancelist april12test1.csv
```
Then display the output like this:
```
$newrun
```
You can then find all the jobs that didn't start like this:
```
$newrun | where-object {$_.result -ne "started"}
```
Once you understand the error you can manually learn the command like this, so you can edit it and run it manually:
```
($newrun | where-object {$_.result -ne "started"}).command
```


#### Monitoring the jobs created by a multi mount by realtime output to the screen
If you just want to see the status output as each job is run, then add **-textoutput**

The output will look like this:
```
New-AGMLibGCEConversionMulti -instancelist april12test1.csv -textoutput

The following command encountered this error:       Instance Name already in use
New-AGMLibGCEConversion -projectname project1 -machinetype n1-standard-2 -instancename "apr12test1centos1" -nic0network "https://www.googleapis.com/compute/v1/projects/project1/global/networks/actifioanz" -nic0subnet "https://www.googleapis.com/compute/v1/projects/project1/regions/australia-southeast1/subnetworks/australia" -region "australia-southeast1" -zone "australia-southeast1-a" -srcid "391360" -appname "Centos1" -serviceaccount "systemstaterecovery@project1.iam.gserviceaccount.com" -preferedsource onvault

The following command started this job:  Job_0867154Optional[Job_0867154] to mount londonsky.c.project1.internal_Image_0499948 started
New-AGMLibGCEConversion -projectname project1 -machinetype n1-standard-2 -instancename "apr12test1centos3" -nic0network "https://www.googleapis.com/compute/v1/projects/project1/global/networks/actifioanz" -nic0subnet "https://www.googleapis.com/compute/v1/projects/project1/regions/australia-southeast1/subnetworks/australia" -region "australia-southeast1" -zone "australia-southeast1-a" -srcid "391360" -appname "Centos3" -serviceaccount "systemstaterecovery@project1.iam.gserviceaccount.com" -preferedsource onvault
```



## Compute Engine Instance Onboarding Automation

If we are onboarding large numbers of Compute Engine Instances or we want to auto protect new instances using automation, we can use a function called: **New-AGMLibGCEInstanceDiscovery**

### Using a CSV file to work with multiple zones and or projects

This function can use a CSV file as input to supply the following data to the function which you specify with:

```-discoveryfile **filename.csv**```

The CSV needs the following columns:

* **credentialid**  This is used to determine which stored credential is used to connect to Google Cloud. Learn this by running Get-AGMLibCredentialSrcID
* **applianceid**  This is used to determine which backup appliance will manage the new Compute Engine Instance. Learn this by running Get-AGMLibCredentialSrcID
* **project**  this is the project where we are going to look for new Compute Engine Instances
* **zone** this is the zone where we are going to look for new Compute Engine Instances

So if you have two projects, then ensure the credential you have added as a Cloud Credential has been added to both projects as a service account in IAM and then add a line in the CSV for each zone in that project where you want to search.  This does mean if you add new zones to your project you will need to update the CSV to search in those zones.

An example CSV file is as follows:
```
credentialid,applianceid,project,zone
6654,143112195179,avwarglab1,australia-southeast2-a
6654,143112195179,avwarglab1,australia-southeast2-b
6654,143112195179,avwarglab1,australia-southeast1-c
```
When you run  ```New-AGMLibGCEInstanceDiscovery``` you have to specify one of these two choices:
* ```-nobackup```  This will add all new Compute Engine Instances it finds without protecting them
* ```-backup```  This will add  all new Compute Engine Instances it finds and for each Instance it will look for a label you specify with ```-usertag```  If the value for that label is the name of an existing policy template, it will automatically protect that instance using that template

An example run is as follows.  In the first zone, no new instances were found.  In the second zone, 3 were found and two protected.   A second run is made on each zone where more than 50 instances need to be processed (since we process 50 at a time).  The third zone had no new VMs.   
```
New-AGMLibGCEInstanceDiscovery -discoveryfile ./disco.csv -backup
```
Output should look like this:
```
count                : 0
totalcount           : 0
credentialid         : 6654
applianceid          : 143112195179
project              : avwarglab1
zone                 : australia-southeast1-c
newgceinstances      : 0
newgceinstancebackup : 0

count                : 3
items                : {@{vm=}, @{vm=}, @{vm=}}
totalcount           : 3
credentialid         : 6654
applianceid          : 143112195179
project              : avwarglab1
zone                 : australia-southeast2-a
newgceinstances      : 3
newgceinstancebackup : 2

count                : 0
totalcount           : 0
credentialid         : 6654
applianceid          : 143112195179
project              : avwarglab1
zone                 : australia-southeast2-b
newgceinstances      : 0
newgceinstancebackup : 0
```

### Using a single command per project/zone

Instead of using a discovery file we can specify the four variables needed by the command:  

* ```-applianceid 141805487622``` The appliance we will use to manage for discovery Compute Engine Instances
* ```-credentialid 259643``` The cloud credential used for discovery
* ```-projectid avwservicelab1``` The Project we will examine for new Compute Engine Instances
* ```-zone australia-southeast1-b``` The Zone we will examine for new Compute Engine Instances

We then specify additional options to control how backups are run:

* ```-backup``` To specify that all discovered Compute Engine Instances should have a backup plan applied
* ```-bootonly``` To specify that all discovered Compute Engine Instances should only have their boot drives protected by any backup plan
* ```-limit xx``` To change the number of instances we grab in each run
* ```-nobackup``` To specify that all discovered Compute Engine Instances should **not** have a backup plan applied
* ```-sltid xxx``` To apply the specified Service Template ID for the backup plan
* ```-sltname xxx``` To apply the specified Service Template Name for the backup plan
* ``` -usertag backupplan``` To look for a user specified label on each VM to determine which SLT to use. In this example the key would be **backupplan**  and the value of the key should be a valid SLT name
* ```-diskbackuplabel diskbackup ``` To look for a user specified lavel on each VM to determine which disks to backup. In this example the key would be **diskbackup**  and the value should be **bootonly**.  If any other value is specified then all disks will be backed up.

So an example command would look like this.  In this example we backup all instances using the sltname found in the **backupplan** label on each instance.
```
GMLibGCEInstanceDiscovery -credentialid 706606 -applianceid 144091747698 -project avwarglab1 -zone australia-southeast2-a -backupplanlabel backupplan -backup
```
In this example we also look for a label called **diskbackup** and any instance with a value of **bootonly** will only have the boot disk protected.
```
New-AGMLibGCEInstanceDiscovery -credentialid 706606 -applianceid 144091747698 -project avwarglab1 -zone australia-southeast2-a -backupplanlabel backupplan -diskbackuplabel diskbackup -backup
```
Here is the same command but with a default sltname... meaning if the isntance does have a backupplan label, it will still be protected with the 'default slt' of 'bronze':
```
New-AGMLibGCEInstanceDiscovery -credentialid 706606 -applianceid 144091747698 -project avwarglab1 -zone australia-southeast2-a -backupplanlabel backupplan -diskbackuplabel diskbackup -backup -sltname bronze
```
Finally this command will discover but not apply backup plan to any discovered instances regardless of label:
```
New-AGMLibGCEInstanceDiscovery -credentialid 706606 -applianceid 144091747698 -project avwarglab1 -zone australia-southeast2-a -nobackup
```
### FAQ

1. How do I tag the VM?    

You can do that by specifying  **-usertag**.   So lets say you add a label to each relevant VM where the label name is *corporatepolicy* and the value is a valid template name, then when you run the command, add **-usertag "corporatepolicy"**

The whole command would look like:
```
New-AGMLibGCEInstanceDiscovery -discoveryfile ./disco.csv -backup -usertag "corporatepolicy"
```
2. How do I learn the names of the templates to use as values for the tags?    

You can either look at Templates in the SLA Architect in Web GUI or run: ```Get-AGMSLT```

3. What if I don't want all instances to be added?   

This function has to add them all to ensure each instance is examined.   If you add them then delete them, they won't be added back in a second run because an Actifio label with a value of **unmanaged** will be added to them.

## Compute Engine Instance Image Audit

When a Compute Engine instance backup is created it is effectively back-ended by persistent disk snapshots.   You may have two scenarios:

1.  You want to validate that the images shown by Backup and DR have matching persistent disk snapshots.    For this we use **Confirm-AGMLibComputeEngineImage**
1.  You want to validate that persistent disk snapshots have matching images in Backup and DR. For this we use **Confirm-AGMLibComputeEngineProject**

### Confirm-AGMLibComputeEngineImage

This command confirms that the Compute Engine Snapshot created by a backup image still exists.  It does this using the GoogleCloud PowerShell module

Lets take an example where we have several compute engine instances we want to validate.  We learn their application IDs like this:
```
Get-AGMApplication -filtervalue apptype=GCPInstance | select id,appname,apptype,managed,{$_.cluster.name} | ft

id      appname   apptype     managed $_.cluster.name
--      -------   -------     ------- ---------------
1524465 bastion   GCPInstance    True melbourne-82270
1524463 windows   GCPInstance    True melbourne-82270
1457056 centos1   GCPInstance    True melbourne-82270
```
We now learn the images for an instance like this:
```
$appid = 1524465
Get-AGMImage -filtervalue appid=$appid | Select-Object id,backupname,consistencydate

id      backupname    consistencydate
--      ----------    ---------------
1845601 Image_0217092 2023-03-08 04:25:31
1842663 Image_0215044 2023-03-07 00:20:31
1832795 Image_0209117 2023-03-05 19:00:12
1826087 Image_0200560 2023-03-04 19:00:12
1813283 Image_0192007 2023-03-03 19:00:12
1796177 Image_0183418 2023-03-02 19:00:12
1791809 Image_0176133 2023-03-01 23:40:55
1745128 Image_0173061 2023-02-23 22:16:47
```
Now that we have the image IDs we can validate them one at a time like this.   There are two things we want to find, which is to confirm there is a matching snapshotname and that the status is READY.
```
$image = 1845601
Confirm-AGMLibComputeEngineImage $image

id           : 1845601
project      : avwarglab1
appliance    : 145666187717
imagename    : Image_0217092
snapshotname : snap-bastion-aed5f6c4-d31c-4789-ad20-0e5f18e06f8b
status       : READY
```
We could validate all the images for one application by doing this:
```
$appid = 1524465
$images = Get-AGMImage -filtervalue appid=$appid | Select-Object id,backupname,consistencydate
foreach ($image in $images) { Confirm-AGMLibComputeEngineImage $image.id }
```
Note that if the GoogleCloud PowerShell module is not installed this function cannot run.

### Confirm-AGMLibComputeEngineProject

This function matches snapshots in compute engine to snapshots in Backup and DR using the GoogleCloud PowerShell module.   This function reads in all Compute Engine snapshots found in the nominated Google Cloud project and then matches them to those reported by Backup and DR.   If an image does not have a reported ID then no matching image was found by Backup and DR.  This means either the image is not being tracked by Backup and DR or is being tracked by a different instance of Backup and DR (a different Management Console and Backup Appliance) 

You run the function like this (change $project to suit your project).  You will get a report on every persistent disk snapshot found in that project.

```
$project = "avwarglab1"
Confirm-AGMLibComputeEngineProject -projectid $project

id           : 1745128
project      : avwarglab1
appliance    : 145666187717
imagename    : image_0173061
snapshotname : snap-bastion-08864128-bbee-4e4b-b45e-5c651b54f043
status       : READY
```
There are theree scenarios:
1.  All fields are populated, then a matching snapshot to image is found
1.  The ID field is not populated but the appliance and imagename fields are, then the image was made by a different instance of backup/dr (different Management Console and backup/recovery appliance)
1.  The ID, appliance and imagename fields are not populated meaning this snapshot was created by compute engine schedule or manually (not by backup/dr).

Note that if the GoogleCloud PowerShell module is not installed this function cannot run.

[Back to top](#usage-examples)

# Connecting or Logging in

To login to a Management Console (or AGM) we use the **Connect-AGM** command.

## Connect-AGM

The Syntax to use Connect-AGM is documented here:

| Product | Device | Instructions
| ---- | ---- | --------
| Actifio | AGM  | [Login to your AGM](https://github.com/Actifio/AGMPowerCLI#4-login-to-your-agm)             
| Google Cloud Backup and DR | Management Console |  [GCBDR](https://github.com/Actifio/AGMPowerCLI/blob/main/GCBDR.md)

[Back to top](#usage-examples)

# Consistency Groups

## Consistency Group Management

There are five commands that you can use to manage consistency groups

* Get-AGMConsistencyGroup
* New-AGMConsistencyGroup
* Remove-AGMConsistencyGroup
* Set-AGMConsistencyGroup
* Set-AGMConsistencyGroupMember

To create a consistency group we need to learn the ID of Appliance we want to create it on and the ID of the Host that it will use applications from:

* Get-AGMAppliance
* Get-AGMHost

We can then use a command like this to create it. Note this group has no members in it:
```
New-AGMConsistencyGroup -groupname "ProdGroup" -description "This is the prod group" -applianceid 70194 -hostid  70631
```
Learn the consistencygroup ID with:

* Get-AGMConsistencyGroup

You can edit the name or description with the following syntax (changing group ID to suit):
```
Set-AGMConsistencyGroup -groupname "bettername" -description "Even better description" -applianceid 70194 -groupid 353953
```
Now we need to add applications to the group.   We need to know the application IDs
Learn member APP IDs with with a filter like this:
```
$targethost = 70631
Get-AGMApplication -filtervalue hostid=$targethost | select id,appname
```
We can then add selected applications to the group with syntax like this.   Comma separate multiple IDs:
```
Set-AGMConsistencyGroupMember -groupid 353953 -applicationid "210647,210645" -add
```
We can remove them from the group with syntax like this:
```
Set-AGMConsistencyGroupMember -groupid 353953 -applicationid "210647,210645" -remove
```
We can delete  the group with syntax like this: 
```
Remove-AGMConsistencyGroup 353953
```
[Back to top](#usage-examples)
# DB2

## Creating a DB2 Mount
This command will create a DB2 mount using a guided menu:
```
New-AGMLibDb2Mount
```
[Back to top](#usage-examples)

# Disaster Recovery Automation

There are several automation tools available to recovery multiple VMs and databases in a single command.  Most of these use a CSV file as an input.  Additional tools are being added based on demand.  

## Recovering Virtual Machines

There are three principal recovery scenarios:

| Production Site  | DR Site | Recovery needed
| ------------- | ------------- | ------------- | 
| Google Cloud Zone | Google Cloud Zone | [Create Multiple Compute Engine instances](#compute-engine-instance-multi-mount-disaster-recovery)
| VMware | Google Cloud VMware Engine | [Zero Footprint DR Automation](https://github.com/Actifio/zfdr)
| VMware | Google Cloud Zone | [Create Multiple Compute Engine instances](#compute-engine-instance-multi-conversion-from-vmware-vm)

## Recoverying Databases

While you can mount any databases using PowerShell, there are also some automation examples to mount many databases at once:

* [SAP HANA](#sap-hana-multi-mount)
* [SQL Server](#sql-server-multi-mount-and-migrate)

[Back to top](#usage-examples)

# Events

## Listing your events
To list events use this command.  The output can be extensive so [filters](README.md/#filtering) and limits are recommended.
```
Get-AGMEvent
```
You can list all filterable fields with this command:
```
Get-AGMEvent -o
```
In this example we use date and limits:
```
Get-AGMEvent -filtervalue "eventdate>2022-11-17" -limit 3
```
[Back to top](#usage-examples)
# FileSystem

## Creating a FileSystem Mount
This command will create a FileSystem mount using a guided menu:
```
New-AGMLibFSMount
```
[Back to top](#usage-examples)
# Hosts

## Adding a Host

To add a host we need to use a command like this where we specify the desired hostname and IP address and supply the clusterid of the Appliance where you want it created which you can learn with [Get-AGMAppliance](#appliances):
```
New-AGMHost -clusterid 144292692833 -hostname "prodhost1" -ipaddress "10.0.0.1"
```

## Finding a Host ID by Host Name

If you know the name of a host but want to find its host ID, then use this command:
```
$nameofhost = "bastion"
Get-AGMLibHostID $nameofhost
```
Output will look like this:
```
id            : 709573
hostname      : bastion
osrelease     :
appliancename : backup-server-29736
applianceip   : 10.0.3.29
appliancetype : Sky
```
## Finding a Host ID by Operating System Type

You can find all hosts with an installed agent (Connector) using an ostype of either ```Linux``` or ```Win32``` using a command like this:
```
Get-AGMLibHostList -ostype Linux
Get-AGMLibHostList -ostype Win32
```
Output will look like this:
```
id     hostname ostype ApplianceName
--     -------- ------ -------------
744253 windows  Win32  backup-server-29736
```
## Listing Your Hosts
We can use this command to display all hosts.  The output may be very long.
```
Get-AGMHost
```
You can list all filterable fields with this command:
```
Get-AGMHost -o
```
In this example we filter on hostname:
```
Get-AGMHost -filtervalue name=bastion
```
## Managing host ports
This command **adds** iSCSI port name iqn1 to host ID 105008 on appliance ID 143112195179:
```
New-AGMHost -applianceid 143112195179 -hostid "12345" iscsiname "iqn1"
```
To learn applianceid, use this command:  ```Get-AGMAppliance``` and use the clusterid as applianceid.  If you have multiple applianceIDs, comma separate them
To learn hostid, use this command:  ```Get-AGMHost```

This command **removes** iSCSI port name iqn1:
```
Remove-AGMHost -applianceid 143112195179 -hostid "12345" iscsiname "iqn1"
```
## Deleting a Host
You can remove a host with the command.  Note you cannot remove a host if there are still applications depending on it.  In this example we learn the host ID and cluster ID:
```
Get-AGMHost -filtervalue hostname=testvm | select id,name,clusterid

id     name   clusterid
--     ----   ---------
430741 testvm 144091747698
```
We then remove it:
```
Remove-AGMHost -id 430741 -clusterid 144091747698
```

## Deleting Stale Hosts

You may have a situation where you have many stale hosts after a DR or failover test.   You can only delete a single host at a time using the GUI, so we can use this multi step process to delete many stale hosts:

The first three commands learn all hosts that have applications ```$hostswithapps``` and then all known hosts ```$allhosts``` which are then compared to generate a list of stale hosts ```$stalehosts``` that are hosts that have no applications:
```
$hostswithapps = Get-AGMApplication | select @{N="id";E={$_.host.id}},@{N="sourcecluster";E={$_.host.sourcecluster}} | sort-object id | get-unique -AsString
$allhosts = Get-AGMhost -filtervalue "hosttype!VMCluster&hosttype!vcenter&hosttype!esxhost" -sort id:asc | select id,sourcecluster
$stalehosts = Compare-Object -ReferenceObject $allhosts -DifferenceObject $hostswithapps -Property id,sourcecluster | where-object {$_.SideIndicator -eq "<="}
```
We then validate if we have stale hosts:
```
$stalehosts.id.count
```
If the count is non-zero and you are curious what these hosts are, we can list them out:
```
foreach ($object in $stalehosts) { Get-AGMHost -id $object.id | select id,hostname,hosttype }
```
We can then delete them with this script:
```
foreach ($object in $stalehosts) { Remove-AGMHost -id $object.id -applianceid $object.sourcecluster }
```
> **Note**:   The ```Remove-AGMHost``` does not currently return a message, so don't be concerned if the deletion appears to be slow or stuck. 


[Back to top](#usage-examples)

# Images

## Image creation with an OnDemand Job

When we want to manually create a new backup image, this is called running an on-demand job.   We can do this with the ```New-AGMLibImage``` command.
You can learn the application ID of the application in question with:  ```Get-AGMApplication```  You may want to use [filters](README.md/#filtering). 
This is a good example of a filter:
```
Get-AGMApplication -filtervalue managed=true -sort appname:asc | select id,appname,apptype
```
Here is an example of the output:
```
id      appname   apptype                                                                                                                                                                         --      -------   -------
1425738 filepath1 LVM Volume
```
In this example we know the application ID so we request a new image.   A snapshot job will automatically run.   If a snapshot policy cannot be found, a direct to onvault job will be attempted.
```
$appid = 1425738
New-AGMLibImage $appid
```
The output will look like this (note the job name is not returned, this is normal):
```
Running this command: New-AGMLibImage  -appid 1425738 -policyid 424958
```
If we want to start a particular policy so we can use the app ID to learn relevant policies:
```
$appid = 425466
Get-AGMLibPolicies -appid $appid
```
We then use the policy ID we learned.  We also added a label:
```
$policyid = 425080
New-AGMLibImage -appid $appid -policyid $policyid -label "Dev image after upgrade"
```
If the application is a database we can use ```-backuptype log``` or ```-backuptype db``` like this:
```
New-AGMLibImage  -appid 2133445 -backuptype log
```

### Tracking jobs

The command to start an on-demand job does not return a jobname, meaning you need to search for the newly created job.
One solution to do this is to start each job with a unique label. If you use a label then we can find the job easily.  First start the job with a label like this:
```
New-AGMLibImage -appid 409016 -label "tinyrun1"
Running this command: New-AGMLibImage  -appid 409016 -policyid 425081 -label tinyrun1
```
Now we search for a job with that label:
```
Get-AGMJobStatus -filtervalue "label=tinyrun1" | select jobname,status,progress,startdate

jobname     status    progress startdate
-------     ------    -------- ---------
Job_0185433 running          7 2022-11-11 09:18:44
```
But the label has to be unique or you can end up in situation like this where we run a second job with the previously used label:
```
New-AGMLibImage -appid 409016 -label "tinyrun1"
```
Output should look like this:
```
Running this command: New-AGMLibImage  -appid 409016 -policyid 425081 -label tinyrun1
```
First we find the old job (because the new job has not started yet):
```
Get-AGMJobStatus -filtervalue "label=tinyrun1" | select jobname,status,progress,startdate
```
Output should look like this:
```
jobname     status    progress startdate
-------     ------    -------- ---------
Job_0185433 succeeded          2022-11-11 09:18:44
```
Now we find the old job and the new job:
```
Get-AGMJobStatus -filtervalue "label=tinyrun1" | select jobname,status,progress,startdate
```
Output should look like this:
```
jobname     status    progress startdate
-------     ------    -------- ---------
Job_0185358 running          7 2022-11-11 09:11:37
Job_0185433 succeeded          2022-11-11 09:18:44
```

## Image creation in bulk using policy ID

One way to create a semi air-gapped solution is to restrict access to the OnVault pool by using limited time windows that are user controlled.
If we create an OnVault or Direct2Onvault policy that never runs, meaning it is set to run everyday except everyday, then the policy will only run when manually requested.

Now since this user story relies on running specific policies for specific groups of apps, we need a way to group them.
There are two ways to achieve this:

* Using unique Templates for each group
* Using LogicalGroups to group your apps.   This is the recommended method.

Once we have done this, then we can use **Start-AGMLibPolicy** to run a job against all apps either for one policy or in one logical group (or both).
So just run the command and follow the prompts to build your command:
```
Start-AGMLibPolicy
```
We then run our command, for instance:
```
Start-AGMLibPolicy -policyid 6393 -backuptype dblog
```
Output should look like this:
```
Starting job for hostname: mysqlsource   appname: mysqlsource   appid: 51919 using: snap policyID: 6393 from SLTName: PDSnaps
Starting job for hostname: mysqltarget   appname: mysqltarget   appid: 36104 using: snap policyID: 6393 from SLTName: PDSnaps
Starting job for hostname: tiny   appname: tiny   appid: 35590 using: snap policyID: 6393 from SLTName: PDSnaps

```
We can then monitor the jobs like this:
```
Get-AGMJob -filtervalue "policyname=OndemandOV" | select status,progress
```
Output should look like this:
```
status  progress
------  --------
running       97
running       98
```
Your logic would work like this:
1. Count the relevant apps.  In this example we have 2.
```
$appgrab = Get-AGMApplication -filtervalue "sltname=FSSnaps_RW_OV"
$appgrab.count
2
```
2. Count the current images.  We currently have 6 OnVault images.
```
$imagegrab = Get-AGMImage -filtervalue "sltname=FSSnaps_RW_OV&jobclass=OnVault"
$imagegrab.count
6
```
3. Run a new OnVault job. 
```
Start-AGMLibPolicy -policyid 25627
```
Output should look like this. We get two jobs started.
```
Starting job for appid 20577 using cloud policy ID 25627 from SLT FSSnaps_RW_OV
Starting job for appid 6965 using cloud policy ID 25627 from SLT FSSnaps_RW_OV
```
4.  Scan for running jobs until they all finish
```
Get-AGMJob -filtervalue "policyname=OndemandOV" | select status,progress

status             progress
------             --------
queued                    0
queued (readiness)        0

Get-AGMJob -filtervalue "policyname=OndemandOV" | select status,progress

status  progress
------  --------
running        2
running        2

Get-AGMJob -filtervalue "policyname=OndemandOV" | select status,progress

status    progress
------    --------
running         98
succeeded      100

Get-AGMJob -filtervalue "policyname=OndemandOV" | select status,progress

status progress
------ --------

```
5. Count the images and ensure they went up by the number of apps.   Note that if expiration run at this time, this will confuse the issue.
You can see here we went from 6 to 8.
```
$imagegrab = Get-AGMImage -filtervalue "sltname=FSSnaps_RW_OV&jobclass=OnVault"
$imagegrab.count
8
```
## Image Expiration
This command expires a single image:
```
Remove-AGMImage Image_2133445
```

## Image Expiration In Bulk

You may have a requirement to expire large numbers of images at one time.   One way to approach this is to use the ```Remove-AGMImage``` command in a loop. However this may fail as shown in the example below.  The issue is that the first expiration job is still running while you attempt to execute the following jobs, which causes a collision:
```
$images = Get-AGMImage -filtervalue appid=35590 | select backupname
$images

backupname
----------
Image_0272391
Image_0270340
Image_0268295
Image_0267271
Image_0266247
Image_0265223
Image_0262151
Image_0259079

foreach ($image in $images)
>> {
>> remove-agmimage -imagename $image.backupname
>> }

err_code err_message
-------- -----------
   10023 avwlab2sky:,	errormessage: expiration in progress, try again later,	errorcode: 10017
   10023 avwlab2sky:,	errormessage: expiration in progress, try again later,	errorcode: 10017
   10023 avwlab2sky:,	errormessage: expiration in progress, try again later,	errorcode: 10017
   10023 avwlab2sky:,	errormessage: expiration in progress, try again later,	errorcode: 10017
   10023 avwlab2sky:,	errormessage: expiration in progress, try again later,	errorcode: 10017
   10023 avwlab2sky:,	errormessage: expiration in progress, try again later,	errorcode: 10017
   10023 avwlab2sky:,	errormessage: expiration in progress, try again later,	errorcode: 10017

```
There are two solutions for this.   Either insert a sleep in between each Remove-AGMImage command, or preferably use the method below, where we set the image expiration date instead:

First we learn the expiration dates
```
$images = Get-AGMImage -filtervalue appid=35590 | select backupname,expiration
$images
```
Output should look like this:
```
backupname    expiration
----------    ----------
Image_0267271 2021-09-18 19:02:27
Image_0266247 2021-09-17 11:03:09
Image_0265223 2021-09-16 10:07:43
```
We then change them all to a date prior to today and confirm they changed:
```
foreach ($image in $images) { Set-AGMImage -imagename $image.backupname -expiration "2021-09-14" }
```
Output should look like this:
```
xml                            backupRest
---                            ----------
version="1.0" encoding="UTF-8" backupRest
version="1.0" encoding="UTF-8" backupRest
version="1.0" encoding="UTF-8" backupRest
```

```
$images = Get-AGMImage -filtervalue appid=35590 | select backupname,expiration
$images
```
Output should look like this:
```

backupname    expiration
----------    ----------
Image_0267271 2021-09-14 00:00:00
Image_0266247 2021-09-14 00:00:00
Image_0265223 2021-09-14 00:00:00
```
The images will expire over the next hour.

#### Using a CSV file

You can also use a CSV file for this by exporting the images to a CSV like this:
```
Get-AGMImage -filtervalue appid=35590 | select backupname,expiration | export-csv -path images.csv
```
Now edit the CSV and then import it:
```
$images = import-csv -path .\images.csv
```
Now change the expiration date for all images imported from the CSV:
```
foreach ($image in $images) { Set-AGMImage -imagename $image.backupname -expiration "2021-09-14" }
```

## Image Expiration For a Deleted Cloud Storage Bucket

If you have a situation where you have deleted a Cloud Storage bucket, then all OnVault operations to that bucket including expirations, will fail.  

At this point you will have images that are stuck.   To clean this up, use the following procedure:

First learn the ID of the affected bucket using this command:
```
Get-AGMDiskPool -filtervalue pooltype=vault | select id,name
```
Typical output will look like this:
```
id      name
--      ----
1065513 badbucketarglab
1065490 autoclasstest
408763  avwargolis
```
Now confirm this pool does represent the bucket that was accidentally deleted:
```
$diskpoolid = 1065513
Get-AGMDiskPool $diskpoolid | select id,@{N="bucket";E={$_.vaultprops.bucket}},@{N="applianceid";E={$_.cluster.clusterid}}
```
Typical output would look like this:
```
id      bucket          applianceid
--      ------          ---------
1065513 badbucketarglab 144091747698
```
Now use the ID as diskpoolid and the applianceid and run this command: 
```
Import-AGMLibOnVault -diskpoolid 1065513 -applianceid 144091747698 -forget
```
Typical output will look like this, where 2 images were forgotten:
```
count items
----- -----
    1 {@{@type=vaultPoolForgetResultRest; imagecount=2; application=}}
```
If there were no images you will see this:
```
count items
----- -----
    0 {}
```
You can now remove the bad pool from any Backup Plan Resource Profiles and then delete the bad pool from Storage Pools.

If you targeted the wrong pool and regret what you just did, simply run the command again without ```-forget``` to import the images.


## Image Import from OnVault

Prior to running your scripts you may want to import the latest OnVault images into your appliance.  To learn the syntax, just run the command without any options.   It will run guided mode.  We can also learn everything we need, step by step as shown below.

In general we just run the command with two parameters like this.
```
Import-AGMLibOnVault -diskpoolid 20060633 -applianceid 1415019931 
```
Learn Diskpool ID with this command.  The appliance named here is the appliance we are importing into.  So its not the source appliance, but the target appliance that is going to use the imported images:
```
Import-AGMLibOnVault -listdiskpools
```
Now take the diskpool ID to learn the appliance ID.  This is the appliance ID of the appliance that made the images:
```
Import-AGMLibOnVault -diskpoolid 199085 -listapplianceids
```
If you want to import a specific application, learn the application ID with this command.  Note the backupcount is the number of images in the pool, not how many will be imported (which could be less):
```
Import-AGMLibOnVault -diskpoolid 199085 -applianceid 1415019931 -listapps
```
Then use the appid you learned to import: 
```
 Import-AGMLibOnVault -diskpoolid 199085 -applianceid 1415019931 -appid 4788
```
Or just import every image in that disk pool:
```
 Import-AGMLibOnVault -diskpoolid 199085 -applianceid 1415019931
```
If you want to monitor the import, add **-monitor** to the command:
```
Import-AGMLibOnVault -diskpoolid 199085 -applianceid 1415019931 -monitor
```
Note you can also add **-forget** to forget learned images, or **-owner** to take ownership of those images.

## Persistent Disk Import From OnVault

Imports or forgets PD Snapshot images.  Note there is no Forget-AGMLibPDSnapshot command.  You can do import and forget from this function. 

Imports all PD Snapshot images from disk pool ID 20060633 onto Appliance ID 1415019931
```
Import-AGMLibPDSnapshot -diskpoolid 20060633 -applianceid 1415019931 
```

Imports all PD Snapshot images from disk pool ID 20060633 and App ID 4788 onto Appliance ID 1415019931:
```
Import-AGMLibPDSnapshot -diskpoolid 20060633 -applianceid 1415019931 -appid 4788
```
Imports all PD Snapshot images from disk pool ID 20060633 and App ID 4788 onto Appliance ID 1415019931 and takes ownership:
```
Import-AGMLibPDSnapshot -diskpoolid 20060633 -applianceid 1415019931 -appid 4788 -owner
```
Forgets all PD Snapshot images imported from disk pool ID 20060633 and App ID 4788 onto Appliance ID 1415019931:
```
Import-AGMLibPDSnapshot -diskpoolid 20060633 -applianceid 1415019931 -appid 4788 -forget
```


## Image restore
For the vast bulk of application types where we want to restore the application, the main thing we need is the image ID that will be used.
First find the application you want to work with:
```
Get-AGMApplication -filtervalue managed=true | select id,appname,apptype
```
This will give you the application ID (in this example it is 425468), which we then use to learn the images:
```
$appid=425468
Get-AGMImage -filtervalue appid=$appid -sort consistencydate:desc | select id,consistencydate,jobclass
```
We then take the image ID and run a restore.   However some application types can restore individual objects which we can specify as an objectlist, so we use this syntax to find the objects:
```
$imageid = 791691
(Get-AGMImage 791691).restorableobjects.name
```
There are a number of parameters we can use:
* $imageid:  The imageid or imagename are mandatory.
* $imagename: The imageid or imagename are mandatory.
* $jsonbody:  This can be used if you know what the desired JSON body is, otherwise use the following parameters:
* $donotrecover:   This is for databases.  Specifies that the Databases is not restored with recovery.
* $disableschedule:  This is a switch that will control whether the schedule will be disabled when a restore is run.  By default it is is false
* $objectlist:  This is a comma separated list of objects to be restored, such as DBs in an instance or Consistency Group
* $username:  This is a username
* $password:  This is the password for the username
* $datastore:  For VMware restores, specifies which datastore will be used for the restored VM
* $poweroffvm:  For VMware restore, specified if the VM should be restored in the powered off state.  By default this is false and the VM is powered on at restore time time.


We then form our command.  This example uses image ID 1234 to restore DB1 and DB2 in Instance or a Consistency Group
```
Restore-AGMApplication -imageid 1234 -objectlist "DB1,DB2" 
```

## Setting an Image Label
You can label an image with a command like this, specifying the imagename and desired label:
```
Set-AGMImage -imagename Image_2133445 -label "testimage"
```

## Setting an Image Label in bulk

This function is used to label a large number of images in a single command.  This is done by supplying one of the following:
* A list of images to label, normally created with ```New-AGMLibImageRange```  We then use:   ```Set-AGMLibImage -imagelist <imagelist>```
* A CSV file contained a list of images with new labels.  The file needs to have at least id,backupname,label as headings.  You could use ```New-AGMLibImageRange``` to create this file.  Then use:  ```Set-AGMLibImage -filename <filename.csv>```
* An imagename.   You could learn this in the Web GUI.   Then use:  ```Set-AGMLibImage -imagename <imagename> -label <newlabel>"```

[Back to top](#usage-examples)

# Installation

Installation on how to install AGMPowerCLI and [AGMPowerLib](https://github.com/Actifio/AGMPowerLib) can be found here:

| Module |  Instructions
| ---- | --------
| AGMPowerCLI|  [Install or Upgrade AGMPowerCLI](https://github.com/Actifio/AGMPowerCLI#1-install-or-upgrade-agmpowercli)             
| AGMPowerLib |  [Install or upgrade AGMPowerLib](https://github.com/Actifio/AGMPowerLib#install-or-upgrade-agmpowerlib)


[Back to top](#usage-examples)

# Jobs

## Displaying Job History
This command will find the history of jobs that are not running or queued, but the output will be long, so always run this command with [filters](README.md/#filtering):
```
Get-AGMJobHistory
```
You can display all valid [filters](README.md/#filtering) with this command:
```
Get-AGMJobHistory -o
```
For instance this command will list the most recent snapshot for appid 992586
```
Get-AGMJobHistory -filtervalue "appid=992586&jobclass=snapshot" -sort id:desc -limit 1
```
If you are unsure if a job is finished or still running, then use this command, again always with [filters](README.md/#filtering):
```
Get-AGMJobStatus -filtervalue "appid=992586&jobclass=snapshot"  -limit 1
```

## Finding Running Jobs

This command will find running and queued jobs, although we recommend you use ```Get-AGMLibRunningJobs```
```
Get-AGMJob
```
To list all running jobs use this command:
```
Get-AGMLibRunningJobs
```
Output will look like this:
```
jobname       : Job_0198174
jobclass      : DirectOnVault
apptype       : VMBackup
hostname      : avw tiny
appname       : AVW Tiny
appid         : 409016
appliancename : backup-server-29736
status        : running
queuedate     : 2022-11-16 12:24:38
startdate     : 2022-11-16 12:24:38
progress      : 0
targethost    :
duration      : 00:00:05
```
You can also use a variety of options:
* ```-every``` To also show queued jobs
* ```-jobclass snapshot``` To only track a specific jobclass such as snapshot
* ```-monitor``` To track all running jobs with automated refresh
* ```-refresh 5``` Used with ```-monitor``` to change the refresh rate in seconds to a different value
* ```-sltname gold``` Track jobs started by a specific policy template, in this example one named *gold*

## Canceling a Running Job
This command will cancel a running job.  You need to know the job name:
```
Remove-AGMJob Job_2133445
```

## Following a Running Job
 
If you have a started a job you might want to track it to completion so you know when its finished.  You can do this with his command:
```
$jobname = "Job_0198174"
Get-AGMLibFollowJobStatus $jobname
```
Output will look like this:
```
jobname     status  progress queuedate           startdate           duration targethost
-------     ------  -------- ---------           ---------           -------- ----------
Job_0198174 running        0 2022-11-16 12:24:38 2022-11-16 12:24:38 00:00:18 esxi-109187.a130d0de.australia-southeast1.gve.goog
```
[Back to top](#usage-examples)
# Logical Groups

Logicial Groups are groups of applications that all share the same backup plan (and nothing else)
## Listing Your Logical Groups
Use this command:
```
Get-AGMLogicalGroup
```
## Listing members in a Logical Group
If we know the logical group ID, we can learn about its members like this:
```
$groupid = 460452
Get-AGMLogicalGroupMember -id $groupid
```
[Back to top](#usage-examples)

# LVM

## Create a new LVM mount

To create a mount from an LVM image, you can build a command in guided mode by just running:
```
 New-AGMLibLVMMount
```
A typical example of a mount would be a command like this one.  Which mounts the latest snapshot of appid 1425738 to host ID 1425591 on appliance ID (clusterid) 145666187717 using the mount point ```/testme```
```
New-AGMLibLVMMount -appid 1425738 -targethostid 1425591 -mountapplianceid 145666187717 -mountaction specifymountlocation -mountlocation "/testme"
```
 Image selection can be done three ways:

1. Run this command in guided mode to learn the available images and select one
1. Learn the imagename and specify that as part of the command with -imagename
1. Learn the Appid and Cluster ID for the appliance that will mount the image and then use -appid and -mountapplianceid .  This will use the latest snapshot, StreamSnap or OnVault image on that appliance

The mount action field is used to determine which mount action to take:
* ```-mountaction agentmanaged```             Will mount using the mount points selected by the agent (this is the default behaviour)
* ```-mountaction  specifymountlocation ```   Will mount using the source paths using a specified mount point that is supplied with ```-mountlocation```
* ```-mountaction nomap ```                   Will mount without mapping the drives


Currently this function does not offer the option to use the source location or limit which LVs get mounted.


[Back to top](#usage-examples)
# Mount

## Active Mounts 

An active image is another term for a mounted image.   In the GUI we display them by going to ```App Manager > Active Mounts```

We can display them by running this command:
```
Get-AGMLibActiveImage
```
Output should look like this:
```
id               : 834142
imagename        : Image_0153552
apptype          : VMBackup
appliancename    : backup-server-29736
hostname         : centos1
appname          : centos1
mountedhost      : avtestmount
allowedip        :
childappname     : avtestmount
consumedsize_gib : 0.237
daysold          : 8
label            : testmount
imagestate       : Mounted

id               : 877783
imagename        : Image_0174903
apptype          : SqlServerWriter
appliancename    : backup-server-29736
hostname         : windows
appname          : CRM
mountedhost      : windows
allowedip        :
childappname     :
consumedsize_gib : 0
daysold          : 6
label            :
imagestate       : Mounted
```
You can filter output with the following filters:
* ```-appid 1234``` To filter on App ID 
* ```-label "labeltext"``` To filter on the label field
* ```-unmount``` To only display images in the unmounted state

## Create a new mount

For many application types there are application specific mount functions such as:

* [Compute Engine Instance Mount](#compute-engine-instance-mount)
* [DB2](#creating-a-db2-mount)
* [FileSystem](#creating-a-filesystem-mount)
* [LVM](#create-a-new-lvm-mount)
* [My SQL](#creating-a-mysql-mount)
* [Oracle](#creating-a-oracle-mount)
* [PostgreSQL](#creating-a-postgresql-mount)
* [SAP HANA](#sap-hana-mount)
* [SQL Server](#sql-server-database-mount)
* [VMWare VM as a new VM](#using-a-vmware-mount-to-create-a-new-vmware-vm)

However you can create a simple file system mount with this command like this:
```
New-AGMMount -imageid 1234 -targethostid 5678
```
If you know the well formed JSON for a mount you could do this:
```
New-AGMMount -imageid 53776703 -jsonbody '{"@type":"mountRest","label":"test mount","host":{"id":"43673548"},"poweronvm":false,"migratevm":false}'
```

## Create a new mount to a Container

This command runs a guided menu to mount an image to a container
```
New-AGMLibContainerMount 
```
In this example we mount Image ID 54380607  The ```-volumes``` list each moint point in the image.  Each mount point is comma separated.  For each each mountpoint we need three values, that are semi-colon separated.  In this example, there are two mount points, the first one is ```/dev/hanavg/log``` .  It is given an appliance mountpoint of ```/test1``` and an NFS export path of ```/custmnt2```

The allowedips is a comma separated list of IP addresses that can connect to the appliance mountpoint.
```
New-AGMLibContainerMount -imageid 54380607 -volumes "dasvol:/dev/hanavg/log;/tmp/cmounts/test1;/custmnt2,dasvol:/dev/hanavg/data;/tmp/cmounts/test2;/ss" -allowedips "1.1.1.1,10.10.10.10"
```

## Display Container Mount YAML

If you have used the option to mount to a Container, you may want to get the YAML file needed to allow the Container to access it.  First learn the mounted image ID or imagename with the [Get-AGMLibActiveImage](#active-mounts) command and then use it like this:
```
$imagename = Image_0174936
Get-AGMLibContainerYAML -imagename $imagename
```

## Multi Mount for Ransomware Analysis

There are many cases where you may want to mount many filesystems in one hit.  A simple scenario is ransomware, where you are trying to find an uninfected or as yet unattacked (but infected) image for each production filesystem.   So lets mount as many images as we can as quickly as we can so we can find unaffected filesystems and start the recovery.

There is a composite function that is designed to help you find all the commands.   You can start this by running:  
```
Start-AGMLibRansomwareRecovery
```

### Stopping the Scheduler and/or expiration 

Prior to beginning recovery efforts you may want to stop the scheduler and expiration on large numbers of Apps or even your whole environment.
If you created Logical Groups this is one convenient way to manage this.   
There are two commands you can use:

* ```Get-AGMLibSLA```      This command will list the Scheduler and Expiration status for all your apps, or if you use -appid or -slaid, for a specific app
* ```Set-AGMLibSLA```      This command will let you set the scheduler or Expiration status for all your apps, specific apps or specific Logical Groups.

#### Building a list of images
First we build an object that contains a list of images.  For this we can use **Get-AGMLibImageRange** in a syntax like this, where in this example we get all images of filesystems created in the last day:
```
$imagelist = Get-AGMLibImageRange -apptype FileSystem -appliancename sa-sky -olderlimit 1
```
If we know that images created in the last 24 hours are all infected, we could use this (up to 3 days old but not less than 1 day old):
```
$imagelist = Get-AGMLibImageRange -apptype FileSystem -appliancename sa-sky -olderlimit 3 -newerlimit 1
```
We can also use the Template Name (SLT) to find our apps.  This is a handy way to separate apps since you can create as many SLTs as you like and use them as a unique way to group apps.
```
$imagelist = Get-AGMLibImageRange -sltname FSSnaps_RW_OV -olderlimit 3 -newerlimit 1
```

#### Editing your $Imagelist 

You could create a CSV of images, edit it and then convert that into an object.  This would let you delete all the images you don't want to recover, or create chunks to recover (say 20 images at a time)

In this example we grab 20 days of images:

```
Get-AGMLibImageRange -apptype FileSystem -appliancename sa-sky -olderlimit 20 | Export-Csv -Path .\images.csv
```

We now edit the CSV  we created **images.csv** to remove images we don't want.   We then import what is left into our $imagelist variable:
```
$imagelist = Import-Csv -Path .\images.csv
```
Now we have our image list, we can begin to create our recovery command.

#### Define our scanning host list
 
We need to define a single host to use as our mount target or an array of hosts.

```
Get-AGMHost -filtervalue "hostname~mysql" | select id,hostname
```
Output should look like this:
```
id   hostname
--   --------
7376 mysqltarget
6915 mysqlsource

$hostlist = @(7376,6915)
```
We could also define a specific host like this:
```
$hostid = 7376
```
#### Run our multi-mount command

We can now fire our new command using the settings we defined and our image list:
```
New-AGMLibMultiMount -imagelist $imagelist -hostlist $hostlist -mountpoint /tmp/
```
For uniqueness we have quite a few choices to generate mounts with useful names.   A numeric indicator will always be added to each mountpoint as a suffix.  Optionally we can use any of the following.   They will be added in the order they are listed here:

* -h or hostnamesuffix   :  which will add the host name of the image to the mountpoint
* -a or -appnamesuffix   :  which will add the appname of the image to the mountpoint
* -i  or -imagesuffix    :  which will add the image name of the image to the mountpoint
* -c or -condatesuffix   :  which will add the consistency date of the image to the mountpoint


This will mount all the images in the list and round robin through the host list.

If you don't specify a label, all the image will get the label **MultiFS Recovery**   This will let you easily spot your mounts by doing this:
```
$mountlist = Get-AGMLibActiveImage | where-object  {$_.label -eq "MultiFS Recovery"}
```
When you are ready to unmount them, run this script:
```
foreach ($mount in $mountlist.imagename)
{
Remove-AGMMount $mount -d
}
```
#### Updating Labels
We can use the following command to update the Label of a specific image:
```
Set-AGMImage
```
However we could update a large number of images with this command:
```
Set-AGMLibImage
```
## Unmounting an Image
We can find mounted image with  [Get-AGMLibActiveImages](#active-mounts) 

Then use this command to unmount and delete a mounted image:
```
$imagename = Image_0174936
Remove-AGMLibMount -imagename $imagename -delete
```
You can also use the following:
* ```-imageid 1234``` To use image ID rather than image name
* ```-force``` To force the unmount.   Don't do this without clear reason
* ```-preservevm ``` This applies to Compute Engine Instances created from Persistent Disk Snapshot.   When used the Appliance Image of the mount is removed, but on the Compute Engine  side the new VM is retained.   
* ```-gceinstanceforget```  Forgets all mounted Compute Engine Instance.  This is the same as running ```-preservevm``` against them
[Back to top](#usage-examples)
# MySQL

## Creating a MySQL Mount
This command will create a MySQL mount using a guided menu:
```
New-AGMLibMySQLMount
```
[Back to top](#usage-examples)
# Oracle

## Creating a Oracle Mount
This command will create a Oracle mount using a guided menu:
```
New-AGMLibOracleMount
```
[Back to top](#usage-examples)
# Organizations

## Organization Creation

If we want to create an Organization we need to get the IDs of the various resources we want to put into the Organization.   We could run a series of commands like this:
```
Get-AGMHost | Select-Object id,name
Get-AGMSLP | Select-Object id,name
Get-AGMSLP | Select-Object id,name
Get-AGMDiskpool | Select-Object id,name
```
Using the IDs we can then form a command like this one:
```
New-AGMOrg -orgname "prod1" -description "this is prod org" -hostlist "460500,442009" -slplist "441943" -sltlist "108758" -poollist "441941"
```
We can then grab the contents of the Org by learning the ID of the Org:
```
Get-AGMOrg
```
Then grab all the contents of the org and display the resources:
```
$org = Get-AGMOrg -orgid 526553
$org.resourcecollection
```
Output will look like this:
```
sltlist       : {108758}
hostlist      : {442009, 460500}
slplist       : {441943}
poollist      : {441941}
sltlistcount  : 1
hostlistcount : 2
slplistcount  : 1
poollistcount : 1
```
We then realize we added the wrong host ID.   We need to remove 460500 and add 449560.   First we remove 460500 by setting the Org to **0**
```
 Set-AGMOrgHost -orglist "0" -hostid 460500
 ```
 We then add 449560 to Org ID 526553
 ```
 Set-AGMOrgHost -orglist "526553" -hostid 449560
 ```
 We then validate, confirming 460500 is gone and 449560 has been added.
 ```
$org = Get-AGMOrg -orgid 526553
$org.resourcecollection.hostlist
442009
449560
```
[Back to top](#usage-examples)
# PostgreSQL

## Creating a PostgreSQL Mount
This command will create a PostgreSQL mount using a guided menu:
```
New-AGMLibPostgreSQLMount
```
[Back to top](#usage-examples)
# SAP HANA

# SAP HANA Mount

In this 'story' a user wants to mount a HANA database from the latest snapshot of a HANA Instance (HDB) to a host. Most aspects of the story are the same as above, however they need some more information to run their mount command. They learn the App ID of the HANA database where ```act``` is the name of the HANA database.
```
Get-AGMLibApplicationID act |ft
```
Output should look like this:
```

id     friendlytype hostname   hostid appname appliancename applianceip applianceid  appliancetype managed
--     ------------ --------   ------ ------- ------------- ----------- -----------  ------------- -------
577110 SAPHANA      coe-hana-1 577093 act     sky1          10.60.1.7   141767697828 Sky              True
```
So now we know the id of the Database inside our HANA instance, we just need to specify the HANA user store key (userstorekey) that has rights to recover the database on the target host (targethostname), a new database SID (dbsid) to use, and lastly to specify a target host filesystem mount point (mountpointperimage) for the HANA instance to run from. We then run our mount command like this:

```
New-AGMLibSAPHANAMount -appid 577110 -targethostname coe-hana-2 -dbsid "TGT" -userstorekey "ACTBACKUP" -mountpointperimage "/tgt" -label "Test HANA database"
```
If you run ```New-AGMLibSAPHANAMount``` in guided mode, you can take the option to generate a CSV file.   This can be used to run ```New-AGMLibSAPHANAMultiMount```

##  SAP HANA Multi Mount

You can run ```New-AGMLibSAPHANAMount``` in guided mode and take the option to generate a CSV file which you can then edit it to mount multiple new SAP HANA instances at once.   A sample file would look like this:
```
appid,appname,mountapplianceid,imagename,targethostid,dbsid,userstorekey,mountpointperimage,label,recoverypoint,mountmode,mapdiskstoallesxhosts,sltid,slpid
835132,"act","144091747698","Image_0160795","749871","act","actbackup","/mount","label1","2022-11-07 17:00:39","nfs","false","108758","706611"
```
The following fields are mandatory:
* ```appname```   the appname field is used to ensure you know which instances you are looking at.   Of course if all your SAP HANA instances are called  ```act``` this still might not help.
* ```mountapplianceid```  this is the id of the appliance that will run the mount.  You can learn this with ```Get-AGMAppliance```
* ```targethostid``` this is the ID of the host we are mounting to.   You can learn this with ```Get-AGMHost```
* ```dbsid```  this is the new DB SID we are creating 
* ```userstorekey```  this is the stored credential the agent will use to authorize its host side activities
* ```mountpointperimage```  this is the mount point where the mount will be placed

The following fields are optional:
* ```appid```  If the appnames are all unique, we don't need appid.  If you are working on an imported image, the source appid may not be useful.  Learn this with ```Get-AGMApplication```
* ```label```  the label is handy as it lets us leave comments about this mount, but it is not mandatory
* ```recoverypoint```  the recoverypoint is only useful if there are logs to roll forward.  You don't have to specify it.   For a mount we don't roll forward logs
* ```mountmode``` VMware only (are we using NFS, vRDM or pRDM)
* ```mapdiskstoallesxhosts```  VMware only (are we mapping to all ESXi hosts)
* ```sltid```  template ID if re-protection is requested. Learn this with ```Get-AGMSLT```
* ```slpid```  profile ID if re-protection is requested. Learn this with ```Get-AGMSLP```

To run the multi-mount you would use this command:
```
New-AGMLibSAPHANAMultiMount -instancelist sapmount.csv
```
## SAP HANA Restore
To restore an SAP HANA database we can use this command which will run a guided menu:
```
Restore-AGMLibSAPHANA 
```
[Back to top](#usage-examples)
# SQL Server

## SQL Server Database Clone

As opposed to a mount which rapidly creates a virtual copy of the database(s) where the data is being accessed via the backup appliance, a clone creates a new full copy of the database on the target host server disk. To do this run this command in guided mode:
```
New-AGMLibMSSQLClone
```

SQL Server Clones are very much like a traditional database restore job to the same host as the source & SQL Instance, or to an alternate target host & SQL Instance. Database names can also be changed for Clones, along with the filenames for data and log files, and also stored in drive and folder locations that a user decides. Here is an example of a clone job for a single database to an alternate host:

```
New-AGMLibMSSQLClone -appid 80988 -cloneapplianceid 145138699730 -targethostid 33666 -sqlinstance "WINSQL-2" -renamedatabasefiles -recoverypoint "latest" -dbrenamelist "Database01,DevDB01" -recoverymodel "Same as source" -overwrite "no" -recoverdb "true" -userlogins "false" -volumes -restorelist "D:\,D:\Dev;E:\,E:\Dev"
```

In the above 'story' a user wants to clone a database to a different target host, using the latest copy of the database (including rolling logs forward) and putting the files in an alternate folder structure.

First we need to learn what the AppID is for the source MS SQL instance:
```
Get-AGMLibApplicationID WINSQL-1 |ft
```
Output should look like this:
```
id    friendlytype hostname hostid appname  appliancename    applianceip    applianceid  appliancetype managed
--    ------------ -------- ------ -------  -------------    -----------    -----------  ------------- -------
80862 SqlInstance  winsql-2 33666  WINSQL-2 au-backup-sky-01 192.168.192.13 145138699730 Sky              True
```

Because applications can have images on multiple appliances, if we don't specify an Image name or Image ID, we need to tell the system which appliance to use for the source image. We do this specifying the clusterid of the relevant appliance with -cloneapplianceid. To learn the clusterids we run this command:
```
Get-AGMAppliance | select-object name,clusterid
```

The user validates the name of the target host:
```
Get-AGMLibHostID winsql-2 |ft
```
Output should look like this:
```
id    hostname osrelease                                    appliancename    applianceip    appliancetype
--    -------- ---------                                    -------------    -----------    -------------
33666 winsql-2 Microsoft Windows Server 2019 (version 1809) au-backup-sky-01 192.168.192.13 Sky
```

The user validates the SQL instance name on the target host. Because the user isn't sure about naming of the hostname they used '~' to get a fuzzy search. Because they couldn't remember the exact apptype for SQL Instance, they again just used a fuzzy search for 'instance':

```
Get-AGMApplication -filtervalue "hostname~winsql-2&apptype~instance" | select pathname
```
Output should look like this:
```
pathname
--------
WINSQL-2
```
To break down this command:
* This starts a clone for a database with ImageID 80862 on target host WinSQL-2 and uses the SQL Instance WINSQL-2.
* Files will be renamed to match the new database name because we didn't specify:  **-dontrenamedatabasefiles**
* The database will be recovered, and also logs will be applied to the most recent available to roll-forward.
* The database will be renamed as DevDB01, where as the source database is called Database01, this has a comma between source name and target name : **source_database_name,cloned_database_name**
* The database will be recovered using the same recovery model as the source, alternatively you can choose: **Simple, Full or Bulk Logged**
* The database will be not overwrite an existing database if one exists with the same name, alternatively you can specify yes, or only if the database is stale : **no, yes, stale**
* The database will be set to RESTORE with RECOVERY, alternatively you can specify false, which will set the database to RESTORE with NORECOVERY mode: **true, falsee**
* Each volume is separated by a semicolon, the two fields for each folder are comma separated.
* In this example, the file **Database01.mdf** found in **D:\Data** will be migrated to **D:\Dev\Data\DevDB01.mdf**
* In this example, the file **Database01_log.ldf** found in **E:\Logs** will be migrated to **E:\Dev\Logs\DevDB01_log.ldf**
* The order of the fields must be **source_volume,targetfolder** so for two files **source_volume1,target_folder1;source_volume2,target_folder2**

We could have specified file clone rather than folder clone, or we could have not specified either and let the files go back to their original locations (provided those locations exist).

Once the job is running, the user finds the running job:

```
Get-AGMLibRunningJobs |ft
```
Output should look like this:
```
jobname     jobclass apptype                    hostname             appname  appid   appliancename    status  queuedate           startdate
-------     -------- -------                    --------             -------  -----   -------------    ------  ---------           ---------
Job_1242018 clone    SqlInstance                winsql-1             WINSQL-1 80988   au-backup-sky-01 running 2022-11-17 13:00:10 2022-11-17 13:00:11
```

The user tracks the job to success:

```
Get-AGMLibFollowJobStatus Job_1242018
```
Output should look like this:
```
jobname     status  progress queuedate           startdate           duration targethost
-------     ------  -------- ---------           ---------           -------- ----------
Job_1242018 running       57 2022-11-17 13:00:10 2022-11-17 13:00:11 00:01:05 winsql-2
```
When it completes we should see ```status=succeeded```
```
jobname    : Job_1242018
status     : succeeded
message    : Success
startdate  : 2022-11-17 13:00:11
enddate    : 2022-11-17 13:02:13
duration   : 00:02:01
targethost : winsql-2
```
The user validates the clone exists:
```
Get-AGMLibApplicationID DevDB01 |ft
```
Output should look like this:
```
id      friendlytype hostname hostid appname appliancename    applianceip    applianceid  appliancetype managed
--      ------------ -------- ------ ------- -------------    -----------    -----------  ------------- -------
1325504 SQLServer    winsql-2 33666  DevDB01 au-backup-sky-01 192.168.192.13 145138699730 Sky              True
```
If the target MS SQL Instance has a "Database Inclusion Rule" set for All databases, or User Databases, then it's very likely that you will see the ```managed = True``` setting, which indicates that your cloned database will be protected on the next snapshot of that instance.


## SQL Server Database Mount

In this 'story' a user wants to mount the latest snapshot of a SQL DB to a host

The user finds the appID for the source DB

```
Get-AGMLibApplicationID smalldb
```
Output should look like this:
```
id      friendlytype hostname appname appliancename applianceip  appliancetype managed
--      ------------ -------- ------- ------------- -----------  ------------- -------
5552336 SQLServer    hq-sql   smalldb sa-sky        172.24.1.180 Sky              True
261762  Oracle       oracle   smalldb sa-sky        172.24.1.180 Sky              True
```

The user validates the name of the target host:

```
Get-AGMLibHostID demo-sql-4
```
Output should look like this:
```

id       hostname   osrelease                                    appliancename applianceip  appliancetype
--       --------   ---------                                    ------------- -----------  -------------
43673548 demo-sql-4 Microsoft Windows Server 2019 (version 1809) sa-sky        172.24.1.180 Sky
```

The user validates the SQL instance name on the target host.  Because the user isn't sure about naming of the hostname  they used '~' to get a fuzzy search.  Because they couldn't remember the exact apptype for SQL instance, they again just used a fuzzy search for 'instance':

```
Get-AGMApplication -filtervalue "hostname~demo-sql-4&apptype~instance" | select pathname
```
Output should look like this:
```
pathname
--------
DEMO-SQL-4
```
Because applications can have images on multiple appliances, if we don't specify an Image name or Image ID, we need to tell the system which appliance to use for the source image.   We do this specifying the clusterid of the relevant appliance with -mountapplianceid.   To learn the clusterids we run this command:
```
Get-AGMAppliance | select-object name,clusterid
```

The user then runs a mount command specifying the source appid, mountapplianceid, target host and SQL Instance and DB name on the target:

```
New-AGMLibMSSQLMount -appid 5552336 -mountapplianceid 1415071155 -targethostname demo-sql-4 -label "test and dev made easy" -sqlinstance DEMO-SQL-4 -dbname avtest

```

The user finds the running job:

```
Get-AGMLibRunningJobs
```
Output should look like this:
```
jobname      jobclass   apptype         hostname                    appname               appid    appliancename startdate           progress targethost
-------      --------   -------         --------                    -------               -----    ------------- ---------           -------- ----------
Job_24358189 mount      SqlServerWriter hq-sql                      smalldb               5552336  sa-sky        2020-06-24 14:50:08       53 demo-sql-4
```

The user tracks the job to success:

```
Get-AGMLibFollowJobStatus Job_24358189
```
Output should look like this:
```
jobname      status  progress queuedate           startdate           duration
-------      ------  -------- ---------           ---------           --------
Job_24358189 running       95 2020-06-24 14:49:33 2020-06-24 14:50:08 00:01:30


jobname      status    message startdate           enddate duration
-------      ------    ------- ---------           ------- --------
Job_24358189 succeeded         2020-06-24 14:50:08         00:01:36
```

The user validates the mount exists:

```
Get-AGMLibActiveImage
```
Output should look like this:
```
imagename      apptype         hostname        appname appid    mountedhostname childappname appliancename consumedsize label
---------      -------         --------        ------- -----    --------------- ------------ ------------- ------------ -----
Image_24358189 SqlServerWriter hq-sql          smalldb 5552336  demo-sql-4      avtest       sa-sky                   0 test and dev made easy
```

The user works with the DB until it is no longer needed.

The user then un-mounts the DB, specifying -d to delete the mount:

```
Remove-AGMMount Image_24358189 -d
```

The user confirms if the mount created a child app
```
Get-AGMLibApplicationID avtest
```
Output should look like this:
```
id       friendlytype hostname   appname appliancename applianceip  appliancetype managed
--       ------------ --------   ------- ------------- -----------  ------------- -------
52410625 SQLServer    demo-sql-4 avtest  sa-sky        172.24.1.180 Sky             False
```

The user deletes the child app:
```
Remove-AGMApplication 52410625
```
### Finding Images if the application is orphaned

Presuming we know the name of our orphan app and the host it once lived on.  Choose the backupname of the image you want by searching for the appname:

```
get-agmimage -filtervalue appname=avdb1 | select id,host,consistencydate,backupname,jobclass | ft *
```
Output should look like this:
```
id      host                   consistencydate     backupname     jobclass
--      ----                   ---------------     ----------     --------
7397674 @{hostname=sydwinsql5} 2020-10-30 13:55:26 Image_10979893 snapshot
7397570 @{hostname=sydwinsql5} 2020-10-30 13:54:16 Image_10979874 snapshot
```

## SQL Server Database Mount and Migrate

In this user story we are going to use SQL Mount and Migrate to move a mount back to server disk

### Create the mount

First we create the mount.  In this example we ran **New-AGMLibMSSQLMount** to build a command.
The final command looks like this:
```
New-AGMLibMSSQLMount -appid 884945 -mountapplianceid 1415071155 -label "test1" -targethostid 655169 -sqlinstance "SYDWINSQL5" -dbname "avtest77"
```

Rather than learn the image ID, we can store the appid and mount appliance ID and then let the system find the latest snapshot:
```
-appid 884945 -mountapplianceid 1415071155
```
We set a label.  This is optional but a very good idea on every mount:
```
-label "test1"
```
We set the target host ID and target SQL instance on that host:
```
-targethostid 655169 -sqlinstance "SYDWINSQL5"
```
We set the DB name for the mounted DB.
```
-dbname "avtest77"
```

### Check the mount
Once the mount has been created, we are ready to start the migrate.   We can check our mount with:  **Get-AGMLibActiveImage**

### Start the migrate

We run **New-AGMLibMSSQLMigrate** to build our migrate command.   The final command looks like this:

```
New-AGMLibMSSQLMigrate -imageid 6859821 -files -restorelist "SQL_smalldb.mdf,D:\Data,d:\avtest1;SQL_smalldb_log.ldf,E:\Logs,e:\avtest1"
```
To break down this command:
* This starts a migrate with default copy thread of 4 and default frequency set to 24 hours for ImageID 6859821.   We could have set thread count and frequency with syntax like:  **-copythreadcount 2 -frequency 2**
* Files will be renamed to match the new database name because we didn't specify:  **-dontrenamedatabasefiles**
* Because **-files** was specified, the **-restorelist** must contain the file name, the source location and the targetlocation.
* Each file is separated by a semicolon,  the three fields for each file are comma separated.
* In this example, the file **SQL_smalldb.mdf** found in **D:\Data** will be migrated to **d:\avtest1**
* In this example, the file **SQL_smalldb_log** found in **E:\Logs** will be migrated to **e:\avtest1**
* The order of the fields must be **filename,sourcefolder,targetfolder** so for two files **filename1,source1,target1;filename2,source2,target2**

We could have specified volume migration rather than file migration, or we could have not specified either and let the files go back to their original locations (provided those locations exist).

### Change migrate settings

To change migrate settings we can run:  **Set-AGMLibMSSQLMigrate** and follow the prompts.  Or we can use syntax like this:
```
Set-AGMLibMSSQLMigrate -imageid 6860452 -copythreadcount 2 -frequency 2
```
This syntax sets the copy threads to 2 and the frequency to 2 hours for Image ID 6860452.   You can learn the image ID with **Get-AGMLibActiveImage -i** or **Set-AGMLibMSSQLMigrate**
This command is the same as using *Update Migration Frequency* in the Active Mounts panel of the Web GUI.
You can check the migration settings with a command like this:
```
Get-AGMImage -id 6859821 | select-object migrate-frequency,migrate-copythreadcount,migrate-configured
```
Output should look like this:
```
migrate-frequency migrate-copythreadcount migrate-configured
----------------- ----------------------- ------------------
               24                       4               True
```

### Cancel the migrate 

If we decide to cancel the migrate we can run this command:
```
Remove-AGMMigrate -imageid 6860452
```
You can learn the image ID with **Get-AGMLibActiveImage -i** or **Set-AGMLibMSSQLMigrate**
This command is the same as using *Cancel Migration* in the Active Mounts panel of the Web GUI.

### Run an on-demand migration job

The frequency you set will determine how often migrate jobs are run.   You can run on-demand migrations with:
```
Start-AGMMigrate -imageid 56072427 
```
This runs a migration job for Image ID 56072427.  You can learn the image ID with **Get-AGMLibActiveImage -i** or **Set-AGMLibMSSQLMigrate**
This command is the same as using *Run Migration Job Now* in the Active Mounts panel of the Web GUI.

You can monitor this job with this command.  We need to know the App ID of the source application.  It will show both running and completed jobs
```
get-agmjobstatus -filtervalue "jobclass=Migrate&appid=884945" | select-object status,startdate,enddate | sort-object startdate
```
Output should look like this:
```
status    startdate           enddate
------    ---------           -------
succeeded 2020-10-09 14:41:55 2020-10-09 14:42:15
succeeded 2020-10-09 14:51:58 2020-10-09 14:52:19
running   2020-10-09 14:54:55
```

### Run a finalize job
When you are ready to switch over, we need to run a finalize with this job:    
```
Start-AGMMigrate -imageid 56072427 -finalize
```
This command runs a Finalize job for Image ID 56072427. You can learn the image ID with **Get-AGMLibActiveImage -i** or **Set-AGMLibMSSQLMigrate**
This command is the same as using *Finalize Migration* in the Active Mounts panel of the Web GUI.

You can monitor this job with this command.  We need to know the App ID of the source application.  It will show both running and completed jobs
```
Get-agmjobstatus -filtervalue "jobclass=Finalize&appid=884945" | select-object status,startdate,enddate | sort-object startdate
```
Output should look like this:
```
status    startdate           enddate
------    ---------           -------
succeeded 2020-10-09 15:02:15 2020-10-09 15:04:06
```

## SQL Server Multi Mount and Migrate

In this user story we are going to use SQL Mount and Migrate to move a Mount back to server disk but we are going to run multiple mounts and migrates in a single pass using a CSV file

This video also documents the process:   https://youtu.be/QX5Sn3XHbCM

### Create the CSV sourcefile

The easiest way to create the CSV file is to run **New-AGMLibMSSQLMount** and take the option to output a CSV file at the end.

Once you have the file then edit it to add additional databases.  
* If you don't know the App ID, then specify the AppName (provided it is unique)
* If you don't know the target host ID, then specify the expected TaregtHostName (provided it is unique)
* If the target host doesn't exist, but you know what the target instance name will be, then make sure to specify **true** in the discovery column

Here is an example of a file:
```
appid,appname,imagename,imageid,mountapplianceid,targethostid,targethostname,sqlinstance,recoverypoint,recoverymodel,overwrite,label,dbname,consistencygroupname,dbnamelist,dbrenamelist,dbnameprefix,dbnamesuffix,recoverdb,userlogins,username,password,base64password,mountmode,mapdiskstoallesxhosts,mountpointperimage,sltid,slpid,discovery,perfoption,migrate,copythreadcount,frequency,dontrenamedatabasefiles,volumes,files,restorelist
,WINDOWS\SQLEXPRESS,,,143112195179,,win-target,WIN-TARGET\SQLEXPRESS,,Same as source,no,sqlinst1,,avcg1,,"model,model1;CRM,crm1",,,TRUE,FALSE,,,,,,,,,,,yes,4,1,,,,
```

### Create the CSV runfile

Where the source file needs to exist before you start,  the runfile will be created the first time you run **New-AGMLibMSSQLMulti** by specifying the name of a new file that doesnt yet exist.
The idea is that you will use this file throughout one DR or test event.   Once all databases are finalized then you can delete the runfile and start your next test using a a new file

If you want to use the latest point in time image, leave imagename and imageid columns empty.   If you want the image rolled forward to the latest log point in time, just enter **latest** in the recoverypoint column.

### Checking image state
At any point in the process, we use **-checkimagestate** to validate whether our mounts exist.  
```
New-AGMLibMSSQLMulti -sourcefile recoverylist.csv  -runfile rundate22052022.csv -checkimagestate
```
The first time you run this command, the output will look like this:
```
id                 :
appname            : WINDOWS\SQLEXPRESS
targethostname     : win-target
childapptype       : ConsistencyGroup
childappname       : avcg1
label              : sqlinst1
previousimagestate :
currentimagestate  : NoMountedImage
```
* id is blank because there is no image yet created by a mount
* previousimagestate is blank because there is no image
* currentimagestate says NoMountedImage because there is no image

### Running the multi mount.
We start all the mounts at once with this command:
```
New-AGMLibMSSQLMulti -sourcefile recoverylist.csv  -runfile rundate22052022.csv -runmount
```
This will run multiple New-AGMLibMSSQLMount jobs.  If run twice, any collisions with existing mounts will not run. 
This means if a mount fails, after you resolve the cause of the issue you can just run the same command again without interfering with existing mounts.
After you run **New-AGMLibMSSQLMulti**  with **-runmount** then check the state with **-checkimagestate**

We expect it to initially show this, where id is still blank, but previousimagestate is telling you a mount was started.
```
id                 :
appname            : WINDOWS\SQLEXPRESS
targethostname     : win-target
childapptype       : ConsistencyGroup
childappname       : avcg1
label              : sqlinst1
previousimagestate : MountStarted
currentimagestate  : NoMountedImage
```
Once the mount job completes we will see this, where the ID is now known and currentimagestate is mounted.
```
id                 : 82789
appname            : WINDOWS\SQLEXPRESS
targethostname     : win-target
childapptype       : ConsistencyGroup
childappname       : avcg1
label              : sqlinst1
previousimagestate : MountStarted
currentimagestate  : Mounted
```
If you run the **-runmount** again, the existing mounts will be unaffected, but previousimagestate will change to: *MountFailed: mount is unsuccessful due to duplicate application on the same host/instance not allowed:*

### Starting the migration
Once all our images are mounted, we can start migrating.   If you run this command with some mounts still running, then migration will only start on those mounts that are ready and you will need to run startmigration again.
```
New-AGMLibMSSQLMulti -sourcefile recoverylist.csv -runfile rundate22052022.csv -startmigration
```
This will start migrate jobs for any SQL Db where the migrate field is set to true.
When you check after migrate has been requested you will see this, where previousimagestate and currentimagestate both say MigrateStarted:
```
id                 : 82789
appname            : WINDOWS\SQLEXPRESS
targethostname     : win-target
childapptype       : ConsistencyGroup
childappname       : avcg1
label              : sqlinst1
previousimagestate : MigrateStarted
currentimagestate  : MigrateStarted
```
Once the first migrate job has finished we will see this where currentimagestate is FinalizeEligible
```
id                 : 82789
appname            : WINDOWS\SQLEXPRESS
targethostname     : win-target
childapptype       : ConsistencyGroup
childappname       : avcg1
label              : sqlinst1
previousimagestate : MigrateStarted
currentimagestate  : FinalizeEligible
```
We can run additional migrate jobs (in addition to the scheduled ones), with this command:
```
New-AGMLibMSSQLMulti -sourcefile recoverylist.csv -runfile rundate22052022.csv -runmigration
```
If you use -runmigration without having first run -startmigration then nothing will happen.

### Starting the finalize
This last option may not be desirable in all cases.  A finalize is disruptive while the switch is made.   You may wish to run this last step one by one using the GUI.  Note if you need multiple finalize jobs per host, you need to run them one at a time.   This might mean running **-finalizemigration** multiple times.
```
New-AGMLibMSSQLMulti -sourcefile recoverylist.csv -runfile rundate22052022.csv -finalizemigration
```
After running the command you will initially see this, where previousimagestate is FinalizeStarted.
```
id                 : 82789
appname            : WINDOWS\SQLEXPRESS
targethostname     : win-target
childapptype       : ConsistencyGroup
childappname       : avcg1
label              : sqlinst1
previousimagestate : FinalizeStarted
currentimagestate  : FinalizeEligible
```
Once finalize is finished you will see this, where currentimagestate is ImageNotFound.  This is normal because at the end of the finalize the mount gets deleted.    Once you see this, validate the DB on the target host and you are complete.
```
id                 : 82789
appname            : WINDOWS\SQLEXPRESS
targethostname     : win-target
childapptype       : ConsistencyGroup
childappname       : avcg1
label              : sqlinst1
previousimagestate : FinalizeStarted
currentimagestate  : ImageNotFound
```

## SQL Server Database Mount with point in time recovery

In this 'story' a user wants to mount a specific snapshot of a SQL DB to a host rolled to a specific point in time.   We start with an appname:

The user finds the appID for the source DB

```
Get-AGMLibApplicationID smalldb
```
Output should look like this:
```
id      friendlytype hostname appname appliancename applianceip  appliancetype managed
--      ------------ -------- ------- ------------- -----------  ------------- -------
5552336 SQLServer    hq-sql   smalldb sa-sky        172.24.1.180 Sky              True
261762  Oracle       oracle   smalldb sa-sky        172.24.1.180 Sky              True

```
We now get a list of images:

```
Get-AGMLibImageDetails 5552336
```
Output should look like this:
```
backupname            jobclass     consistencydate     endpit
----------            --------     ---------------     ------
Image_24351142        snapshot     2020-06-24 11:55:37 2020-06-25 15:07:16
Image_24386274        snapshot     2020-06-25 11:46:22 2020-06-25 15:07:16
```
We have two snapshots and logs as well.

The user runs a mount command specifying the source appid, target host and SQL Instance and DB name on the target as well as a recovery point in ISO 860 format and image name.  However they specify the wrong date, one earlier than the consistency point:

```
New-AGMLibMSSQLMount -imagename Image_24351142 -appid 5552336 -targethostname demo-sql-4 -label "test and dev made easy" -sqlinstance DEMO-SQL-4 -dbname avtest -recoverypoint "2020-06-23 16:00"
```
Output should look like this:
```
errormessage
------------
Specified recovery point 2020-06-23 16:00 is earlier than image consistency date 2020-06-24 11:55:37.  Specify an earlier image.

```
They fix the date and successfully run the command:
```
New-AGMLibMSSQLMount -imagename Image_24351142 -appid 5552336 -targethostname demo-sql-4 -label "test and dev made easy" -sqlinstance DEMO-SQL-4 -dbname avtest -recoverypoint "2020-06-24 16:00"
```

## SQL Server Instance mount

In this 'story' a user wants to mount two databases from the latest snapshot of a SQL Instance to a host.  Most aspects of the story are the same as above, however they need some more information to run their mount command.   They learn the App ID of the SQL Instance:

```
Get-AGMLibApplicationID  HQ-SQL
```
Output should look like this:
```
id      friendlytype hostname appname appliancename applianceip  appliancetype managed
--      ------------ -------- ------- ------------- -----------  ------------- -------
5534398 SqlInstance  hq-sql   HQ-SQL  sa-sky        172.24.1.180 Sky              True
```

We now learn the instance members:
```
Get-AGMApplicationInstanceMember 5534398
```
Output should look like this:
```
rule            : exclude
totaldb         : 9
includecount    : 4
excludecount    : 4
ineligiblecount : 1
ineligiblelist  : {@{id=5552336; appname=smalldb; apptype=SqlServerWriter; srcid=4808; sensitivity=0; systemdb=False; ispartofmemberrule=False; appstate=0}}
eligiblelist    : {@{id=5552340; appname=ReportServer; apptype=SqlServerWriter; srcid=4810; sensitivity=0; systemdb=False; ispartofmemberrule=True; appstate=0}, @{id=5552338; appname=ReportServerTempDB; apptype=SqlServerWriter;
                  srcid=4809; sensitivity=0; systemdb=False; ispartofmemberrule=True; appstate=0}, @{id=5552346; appname=master; apptype=SqlServerWriter; srcid=4813; sensitivity=0; systemdb=False; ispartofmemberrule=True; appstate=0},
                  @{id=50805022; appname=model; apptype=SqlServerWriter; srcid=23401122; sensitivity=0; systemdb=False; ispartofmemberrule=False; appstate=0}…}               
```

However the eligible list is not easy to read, so lets expand it and put it into a table.  This is much easier to read:

```
Get-AGMApplicationInstanceMember 5534398 | Select-Object -ExpandProperty eligiblelist | ft
```
Output should look like this:
```
id       appname            apptype         srcid    sensitivity systemdb ispartofmemberrule appstate
--       -------            -------         -----    ----------- -------- ------------------ --------
5552340  ReportServer       SqlServerWriter 4810               0    False               True        0
5552338  ReportServerTempDB SqlServerWriter 4809               0    False               True        0
5552346  master             SqlServerWriter 4813               0    False               True        0
50805022 model              SqlServerWriter 23401122           0    False              False        0
5552342  msdb               SqlServerWriter 4811               0    False               True        0
5552334  smalldb1           SqlServerWriter 4805               0    False              False        0
5552332  smalldb2           SqlServerWriter 4804               0    False              False        0
5552330  smalldb3           SqlServerWriter 4803               0    False              False        0
```
So now we know the names of the DBs inside our SQL instance, we just need to chose a Consistency group name  to hold them and any prefixes and suffixes we want to use.  We then run our mount command like this:

```
 New-AGMLibMSSQLMount -appid 5534398 -targethostname demo-sql-5 -label "AV instance mount" -sqlinstance DEMO-SQL-5 -consistencygroupname avcg -dbnamelist "smalldb1,smalldb2" -dbnameprefix "testdev_" -dbnamesuffix "_av"
```

## SQL Server Protecting and Rewinding Child Apps

In this story, we create a child app of a SQL DB that is protected by an on-demand template.

First we create the child app.   There are several things about this command.   Firstly it does not specify an image ID, it will just use the latest snapshot.   It specifies the SLTID and SLPID to manage the child app.  This command was generated by running **New-AGMLibMSSQLMount** in guided mode.  
```
New-AGMLibMSSQLMount -appid 884945 -mountapplianceid 1415071155  -label "avtest" -targethostid 655169 -sqlinstance "SYDWINSQL5" -dbname "avtestrp10" -sltid 6318469 -slpid 655697
```
We validate the child app was created:
```
Get-AGMLibApplicationID avtestrp10

id            : 6403028
friendlytype  : SQLServer
hostname      : sydwinsql5
appname       : avtestrp10
appliancename : sydactsky1
applianceip   : 10.65.5.35
appliancetype : Sky
managed       : True
slaid         : 6403030
```
We run an on-demand snapshot of the child app (the mount) when we are ready to make that first bookmark:
```
New-AGMLibImage -appid 6403028
```
Output should look like this:
```
jobname     status  queuedate           startdate
-------     ------  ---------           ---------
Job_9900142 running 2020-09-04 17:00:41 2020-09-04 17:00:41
```
The image is created quickly:
```
Get-AGMLibLatestImage 6403028
```
Output should look like this:
```
appliance       : sydactsky1
hostname        : sydwinsql5
appname         : avtestrp10
appid           : 6403028
jobclass        : snapshot
backupname      : Image_9900142
id              : 6403125
consistencydate : 2020-09-04 17:01:06
endpit          :
sltname         : bookmarkOnDemand
slpname         : Local Only
policyname      : SnapOnDemand
```
We can now continue to use our development child-app in the knowledge we can re-wind to a known good point.    

If we need to re-wind, we simply run the following command, referencing the image ID:
```
Restore-AGMLibMount -imageid 6403125
```
We learn the jobname with this command:
```
Get-AGMLibRunningJobs | ft *
```
We then monitor the job, it runs quickly as its a rewind
```
Get-AGMLibFollowJobStatus Job_9900239
```
Output should look like this:
```
jobname   : Job_9900239
status    : succeeded
message   : Success
startdate : 2020-09-04 17:03:47
enddate   : 2020-09-04 17:05:08
duration  : 00:01:20
```
We can then continue to work with our child app, creating new snapshots or even new child apps using those snapshots.

[Back to top](#usage-examples)
# Storage Pools

## Listing your Storage Pools
To list your storage pools use this command:
```
Get-AGMDiskPool
```
[Back to top](#usage-examples)
# VMware

## Using a VMware mount to create a new VMware VM
To create a new VMware VM from backup use this command which runs a guided menu:
```
New-AGMLibVM 
```
In this example we mount image ID 53773979 as a new VM called testvm9 to the specified vCenter/ESX host.  
Valid values for mountmode are:   nfs, vrdm or prdm with nfs being the default if nothing is selected.
```
New-AGMLibVM -imageid 53773979 -vmname avtestvm9 -datastore "ORA-RAC-iSCSI" -vcenterid 5552150 -esxhostid 5552164 -mountmode nfs 
```
There are several mandatory parameters:
* ```-vmname www```  Specifies the name of the new VMware VM
* ```-vcenterid xxx``` Specifies the vCenter that will manage the VM
* ```-esxhostid yyy```  Specifies the ESXi host where the VM will run
* ```-datastore zzz``` Specifies the name of the datastore where we will store the VMX file and VM swap file

Image selection will be determined by:

* ```-appid nnn```       If you specify this, then the most recent image for that app will be mounted.  This is the most exact choice to get the latest image.
* ```-appname aaa```     If you specify this, then the most recent image for that app will be mounted provided the appname is unique.   If the appname is not unique, then you will need to switch to appid.
* ```-imageid iii```     If you specify this, then this image will be mounted. You will need to learn this imageid before you run the command.
* ```-imagename mmm```   If you specify this, then this image will be mounted. You will need to learn this imagename before you run the command.
* ```-onvault true```    Will use the latest OnVault image rather than latest snapshot image when used with ```-appid``` or ```-appname```

If mounting from OnVault we can use this:
*  ```-perfoption <choice>```    You can specify either:  **StorageOptimized**, **Balanced**, **PerformanceOptimized** or **MaximumPerformance**.   Note if you run this option when mounting a snapshot image, the mount will fail

There are some other options:
* ```-label LLLL```   To set a label
* ```-restoremacaddr``` This will assign the MAC Address from the source VM to the target VM.   Do this in DR situations where you need to preserve the MAC Address

Monitoring options:
* ```-wait```     This will wait up to 2 minutes for the job to start, checking every 15 seconds to show you the job name
* ```-monitor```  Same as -wait but will also run Get-AGMLibFollowJobStatus to monitor the job to completion 



## Mounting a VMware VM backup to an existing VM
To mount to an existing host use this command:
```
New-AGMLibVMExisting
```

## VMware Multi Mount

There are many cases where you may want to mount many VMs in one hit.  A simple scenario is ransomware, where you are trying to find an uninfected or as yet unattacked (but infected) image for each production VM.   So lets mount as many images as we can as quickly as we can so we can find unaffected VMs and start the recovery.

There is a composite function that is designed to help you find all the commands.   You can start this by running:  
```
Start-AGMLibRansomwareRecovery
```


### Building a list of images
First we build an object that contains a list of images.  For this we can use Get-AGMLibImageRange in a syntax like this:
```
$imagelist = Get-AGMLibImageRange
```
In this example we get all images of VMs created in the last day:
```
$imagelist = Get-AGMLibImageRange -apptype VMBackup -appliancename sa-sky -olderlimit 1
```
If we know that images created in the last 24 hours are all infected, we could use this (up to 3 days old but not less than 1 day old):
```
$imagelist = Get-AGMLibImageRange -apptype VMBackup -appliancename sa-sky -olderlimit 3 -newerlimit 1
```
We can also use the Template Name (SLT) to find our apps.  This is a handy way to separate apps since you can create as many SLTs as you like and use them as a unique way to group apps.
```
$imagelist = Get-AGMLibImageRange -sltname FSSnaps_RW_OV
```

### Editing your $Imagelist 

You could create a CSV of images, edit it and then convert that into an object.  This would let you delete all the images you don't want to recover, or create chunks to recover (say 20 images at a time)

In this example we grab 20 days of images:

```
Get-AGMLibImageRange -apptype VMBackup -appliancename sa-sky -olderlimit 20 | Export-Csv -Path .\images.csv
```

We now edit the CSV  we created **images.csv** to remove images we don't want.   We then import what is left into our $imagelist variable:
```
$imagelist = Import-Csv -Path .\images.csv
```
Now we have our image list, we can begin to create our recovery command.

### Define our VMware environment 
 
First we learn our vcenter host ID and set id:
```
Get-AGMHost -filtervalue "isvcenterhost=true" | select id,hostname,srcid
```
Output should look like this:
```
id      hostname                  srcid
--      --------                  -----
5552172 scvmm.sa.acme.com          4661
5552150 hq-vcenter.sa.acme.com     4460
5534713 vcenter-dr.sa.acme.com     4371

$vcenterid = 5552150
```
Now learn your ESXHost IDs and make a simple array.  We need to choose ESX hosts thatr have datastores in common, because we are going to round robin across the ESX hosts and datastores.
```
Get-AGMHost -filtervalue "isesxhost=true&vcenterhostid=4460" | select id,hostname
```
Output should look like this:
```
id       hostname
--       --------
26534616 sa-esx8.sa.acme.com
5552168  sa-esx6.sa.acme.com
5552166  sa-esx5.sa.acme.com
5552164  sa-esx1.sa.acme.com
5552162  sa-esx2.sa.acme.com
5552160  sa-esx4.sa.acme.com
5552158  sa-esx7.sa.acme.com

$esxhostlist = @(5552166,5552168)
$esxhostlist
5552166
5552168
```
Now make an array of datastores:
```
$datastorelist = ((Get-AGMHost -id 5552166).sources.datastorelist | select-object name,freespace | sort-object name | Get-Unique -asstring | select name).name

$datastorelist
IBM-FC-V3700
Pure
```
### Run our multi-mount command

We can now fire our new command using the VMware settings we defined and our image list:
```
New-AGMLibMultiVM -imagelist $imagelist -vcenterid $vcenterid -esxhostlist $esxhostlist -datastorelist 
```
For uniqueness we have quite a few choices to generate VMs with useful names.   If you do nothing, then a numeric indicator will be added to each VM as a suffix.  Otherwise we can use:

* -prefix xxxx           :   where xxxx is a prefix
* -suffix yyyy           :   where yyyy is a suffix
* -c or -condatesuffix   :  which will add the consistency date of the image as a suffix
* -i  or -imagesuffix    :  which will add the image name of the image as a suffix

This will mount all the images in the list and round robin through the ESX host list and data store list.

If you don't specify a label, all the VMs will get the label **MultiVM Recovery**   This will let you easily spot your mounts by doing this:
```
$mountlist = Get-AGMLibActiveImage | where-object  {$_.label -eq "MultiVM Recovery"}
```
When you are ready to unmount them, run this script:
```
foreach ($mount in $mountlist.imagename)
{
Remove-AGMMount $mount -d
}
```

#### esxhostid vs esxhostlist

You can just specify one esxhost ID with -esxhostid.   If you are using NFS datastore and you will let DRS rebalance later, this can make things much faster

#### datastore vs datastorelist

You can also specify a single datastore rather than a list.

[Back to top](#usage-examples)
# Workflows

## Checking the Status of a Workflow
We can check the status of a workflow with this command.  If you don't know the ID, it will help you find it.
```
Get-AGMLibWorkflowStatus
```
You can then use other options to work with a specific workflow ID:
* ```-workflowid 1234``` To see a specific workflow, in this example workflow ID 1234
* ```-monitor``` To monitor a running workflow when used with ```-workflowid 1234```
* ```-previous``` To see the previous run of the workflow when used with ```-workflowid 1234```


## Running a Workflow

Note there is no function to create Workflows, so continue to use the GUI for this.   
There are two functions for workflows:

* Get-AGMLibWorkflowStatus
* Start-AGMLibWorkflow 

For both commands, you don't need any details, just run the command and a wizard will run.   You can use this to learn things like workflow IDs and App IDs so that you can then use these commands as part of automation.

We can start a workflow with a command like this:
```
Start-AGMLibWorkflow -workflowid 9932352
```
We can then run a refresh of this workflow with this command:
```
Start-AGMLibWorkflow -workflowid 9932352 -refresh
```
To find out the status of the workflow and follow the progress, use -m (for monitor mode) as it will follow the workflows progress till it stops running:
```
Get-AGMLibWorkflowStatus -workflowid 9932352 -m
```
We shoud see something like this:
```
status    : RUNNING
startdate : 2020-10-17 11:52:55
enddate   :
duration  : 00:00:03
result    :
jobtag    : avtestwf_momuser_1404389_9932352_10715728

status    : SUCCESS
startdate : 2020-10-17 11:52:55
enddate   : 2020-10-17 11:55:26
duration  : 00:02:31
result    :
jobtag    : avtestwf_momuser_1404389_9932352_10715728
```
If we want to see the results from the previous run, we can use -p (for previous) like this:
```
Get-AGMLibWorkflowStatus -workflowid 9932352 -p
```
If you want to find any jobs that were ran (or are running) by that workflow, use the job_tag like this:
```
Get-AGMJobStatus -filtervalue jobtag=avtestwf_momuser_1404389_9932352_10715570
```
For example:
```
Get-AGMJobStatus -filtervalue jobtag=avtestwf_momuser_1404389_9932352_10715728 | select-object jobclass,status,startdate,enddate

jobclass    status    startdate           enddate
--------    ------    ---------           -------
reprovision running   2020-10-17 11:52:57  

Get-AGMJobStatus -filtervalue jobtag=avtestwf_momuser_1404389_9932352_10715728 | select-object jobclass,status,startdate,enddate

jobclass    status    startdate           enddate
--------    ------    ---------           -------
reprovision succeeded 2020-10-17 11:52:57 2020-10-17 11:55:08
```

[Back to top](#usage-examples)
