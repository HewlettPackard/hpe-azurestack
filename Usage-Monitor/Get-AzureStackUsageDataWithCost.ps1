#
#(C) Copyright 2018 Hewlett Packard Enterprise Development LP 
  
# Permission is hereby granted, free of charge, to any person obtaining a 
# copy of this software and associated documentation files (the "Software"), 
# to deal in the Software without restriction, including without limitation 
# the rights to use, copy, modify, merge, publish, distribute, sublicense, 
# and/or sell copies of the Software, and to permit persons to whom the 
# Software is furnished to do so, subject to the following conditions: 
#  
# The above copyright notice and this permission notice shall be included 
# in all copies or substantial portions of the Software. 
#  
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR 
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
# OTHER DEALINGS IN THE SOFTWARE. 
#
#
<#
    .Synopsis
    Exports AzureStack usage meters data with cost to json file
    .DESCRIPTION
    This entire script is a based on the Usagesummary.ps1 script that is available in the AzureStack-Tools
    repository on github. This script adds ability to store the usage data results to a json file. 
    .EXAMPLE
      1. To get AzureStack Admin usage report with hourly granularity
	      .\Get-AzsUsageInfo.ps1 -StartTime 3/01/2018 -EndTime 3/21/201 -AzureStackDomain azurestack.local `
			 -AzureStackRegion "local" -AzureStackCloudName "Local MAS Cloud" -AADDomain mydir.onmicrosoft.com `
			 -Granularity Hourly 

		  The generated output file will be <AzureStackRegion>-<AzureStackDomain>-Hourly-UsageSummary.json

       2. To get AzureStack tenant usage report with daily granularity
	      .\Get-AzsUsageInfo.ps1 -StartTime 3/01/2018 -EndTime 3/21/2018 -AzureStackDomain azurestack.local `
			-AzureStackRegion "local" -AzureStackCloudName "Local MAS Cloud" -AADDomain mydir.onmicrosoft.com `
			-Granularity Daily -TenantUsage

		  The generated output file will be <AzureStackRegion>-<AzureStackDomain>-Daily-TenantUsageSummary.json
#>

Param
(
	[Parameter(Mandatory = $false, HelpMessage = "Credentials Object")]
	[System.Management.Automation.PSCredential]$Creds,
    [Parameter(Mandatory = $true, HelpMessage = "Enter date as mm/dd/yyyy")]
    [datetime]
    $StartTime,
    [Parameter(Mandatory = $true, HelpMessage = "Enter date as mm/dd/yyyy")]
    [datetime]
    $EndTime ,
    [Parameter(Mandatory = $true, HelpMessage = "ARM endpoint for AzureStack w/o regionName(example: azurestack.local)")]
    [String]
	[ValidateNotNullOrEmpty()]
    $AzureStackDomain ,
    [Parameter(Mandatory = $true, HelpMessage = "AzureStack region name (example: west or Seattle or local)")]
    [String]
	[ValidateNotNullOrEmpty()]
    $AzureStackRegion = "local",
    [Parameter(Mandatory = $true, HelpMessage = "Descriptive name for AzureStack (example: Local MAS Cloud)")]
    [String]
	[ValidateNotNullOrEmpty()]
    $AzureStackCloudName = "Local MAS Cloud",
    [Parameter(Mandatory = $true, HelpMessage = "Azure AD directory name (example: mymas01.onmicrosoft.com)")]
	[ValidateNotNullOrEmpty()]
    [String]
    $AADDomain ,
    [Parameter(Mandatory = $false, HelpMessage = "Hourly or Daily")]
    [ValidateSet("Hourly", "Daily")]
    [String]
    $Granularity = "Hourly",
    [Parameter(Mandatory = $false, HelpMessage = "Optional: Specify this parameter to extract TenantUsage")]
    [Switch]
    $TenantUsage
)

#Helper function to create an empty tenant object
function CreateEmptyTenantObject() {
	$tenantObj = New-Object -TypeName System.Object
	$tenantObj | Add-Member -Name TenantId -MemberType NoteProperty -Value ""
	$tenantObj | Add-Member -Name Owner -MemberType NoteProperty -Value ""
	$tenantObj | Add-Member -Name SubscriptionId -MemberType NoteProperty -Value ""
	$tenantObj | Add-Member -Name DelegatedProviderSubscriptionId -MemberType NoteProperty -Value ""
	$tenantObj | Add-Member -Name DisplayName -MemberType NoteProperty -Value ""
	$tenantObj | Add-Member -Name RoutingResourceManagerType -MemberType NoteProperty -Value ""
	$tenantObj | Add-Member -Name OfferId -MemberType NoteProperty -Value ""
	$tenantObj | Add-Member -Name State -MemberType NoteProperty -Value ""
	return $tenantObj
}

#Helper function to export resource usage from AzureStack
function Export-AzureStackUsage {
    Param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $StartTime1,
        [Parameter(Mandatory = $true)]
        [String]
        $EndTime1 ,
        [Parameter(Mandatory = $true)]
        [String]
        $AzureStackDomain1 ,
        [Parameter(Mandatory = $true)]
        [String]
        $AADDomain1 ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Hourly", "Daily")]
        [String]
        $Granularity1 = 'Hourly',
        [Parameter (Mandatory = $false)]
        [PSCredential]
        $Credential,
        [Parameter(Mandatory = $false)]
        [Switch]
        $TenantUsage1,
        [Parameter(Mandatory = $false)]
        [String]
        $Region = 'local',
        [Parameter(Mandatory = $false)]
        [String]
        $CloudName1 
    )

	
	#Get stack admin subscriptions
	$stackAdminSubscriptionsList = @{}
	Get-AzureRmSubscription | ForEach-Object {
		$stackadminSubRecord = New-Object -TypeName System.Object
		$stackadminSubRecord | Add-Member -Name SubscriptionName -MemberType NoteProperty -Value $_.Name
		$stackadminSubRecord | Add-Member -Name SubscriptionId -MemberType NoteProperty -Value $_.Id
		$stackAdminSubscriptionsList.Add($_.Name,$stackadminSubRecord)
	}	
	$defaultProviderSub = ($stackAdminSubscriptionsList["Default Provider Subscription"]).SubscriptionId
	
	Select-AzureRmSubscription -Subscription "Default Provider Subscription"
    #Obtain Azure Resource Manager Context for Stack
    $ctx = Get-AzureRmContext

    #Get default subscription ID
    if (!$ctx.Subscription){
        Write-Host -ForegroundColor Red "Please Connect To Azure Stack"
        Return
    }
	
    #Setup REST call variables
    $tokens = $ctx.TokenCache.ReadItems()
    $token = $tokens |  Where Resource -eq $ctx.Environment.ActiveDirectoryServiceEndpointResourceId | Sort ExpiresOn | select -Last 1
    $headers = @{ Authorization = ('Bearer {0}' -f $token.AccessToken) }
    $armEndpoint = $ctx.Environment.ResourceManagerUrl

    #Get all current subscriptions from AzureStack
	$uri = $armEndpoint + '/subscriptions/{0}/providers/Microsoft.Subscriptions.Admin/subscriptions?api-version=2015-11-01' -f $defaultProviderSub
    $result = Invoke-RestMethod -Method GET -Uri $uri  -Headers $headers -ErrorVariable RestError -Verbose
	if ($RestError) {
		Write-Host -ForegroundColor Red "Error calling API.."
		return
	}

    $currentSubscriptionList = @{}
    $result.value | ForEach-Object {
		$tenantSubRecord = New-Object -TypeName System.Object
		$tenantSubRecord | Add-Member -Name TenantId -MemberType NoteProperty -Value $_.tenantId
		$tenantSubRecord | Add-Member -Name Owner -MemberType NoteProperty -Value $_.owner
		$tenantSubRecord | Add-Member -Name SubscriptionId -MemberType NoteProperty -Value $_.subscriptionId
		$tenantSubRecord | Add-Member -Name DelegatedProviderSubscriptionId -MemberType NoteProperty -Value $_.delegatedProviderSubscriptionId
		$tenantSubRecord | Add-Member -Name DisplayName -MemberType NoteProperty -Value $_.displayName
		$tenantSubRecord | Add-Member -Name RoutingResourceManagerType -MemberType NoteProperty -Value $_.routingResourceManagerType
		$tenantSubRecord | Add-Member -Name OfferId -MemberType NoteProperty -Value $_.offerId
		$tenantSubRecord | Add-Member -Name State -MemberType NoteProperty -Value $_.state

		$currentSubscriptionList.Add($_.subscriptionId,$tenantSubRecord)
    }

    if(!$currentSubscriptionList) {
		Write-Host -ForegroundColor Red "Failed to obtain user subscriptions list from AzureStack $Region.$AzureStackDomain1"
		return
    }
    Write-Host -ForegroundColor Green "User subscriptions found : " $currentSubscriptionList.Count
	
    #Initialise result count and meter hashtable
    $TotalRecords = 0
    $azsmeters = @{
        'F271A8A388C44D93956A063E1D2FA80B' = 'Static IP Address Usage'
        '9E2739BA86744796B465F64674B822BA' = 'Dynamic IP Address Usage'
        'B4438D5D-453B-4EE1-B42A-DC72E377F1E4' = 'TableCapacity'
        'B5C15376-6C94-4FDD-B655-1A69D138ACA3' = 'PageBlobCapacity'
        'B03C6AE7-B080-4BFA-84A3-22C800F315C6' = 'QueueCapacity'
        '09F8879E-87E9-4305-A572-4B7BE209F857' = 'BlockBlobCapacity'
        'B9FF3CD0-28AA-4762-84BB-FF8FBAEA6A90' = 'TableTransactions'
        '50A1AEAF-8ECA-48A0-8973-A5B3077FEE0D' = 'TableDataTransIn'
        '1B8C1DEC-EE42-414B-AA36-6229CF199370' = 'TableDataTransOut'
        '43DAF82B-4618-444A-B994-40C23F7CD438' = 'BlobTransactions'
        '9764F92C-E44A-498E-8DC1-AAD66587A810' = 'BlobDataTransIn'
        '3023FEF4-ECA5-4D7B-87B3-CFBC061931E8' = 'BlobDataTransOut'
        'EB43DD12-1AA6-4C4B-872C-FAF15A6785EA' = 'QueueTransactions'
        'E518E809-E369-4A45-9274-2017B29FFF25' = 'QueueDataTransIn'
        'DD0A10BA-A5D6-4CB6-88C0-7D585CEF9FC2' = 'QueueDataTransOut'
		'FAB6EB84-500B-4A09-A8CA-7358F8BBAEA5' = 'Base VM Size Hours'
		'9cd92d4c-bafd-4492-b278-bedc2de8232a' = 'Windows VM Size Hours'
		'6DAB500F-A4FD-49C4-956D-229BB9C8C793' = 'VM size hours'
		'380874f9-300c-48e0-95a0-d2d9a21ade8f' = "S4"
		'1b77d90f-427b-4435-b4f1-d78adec53222' = "S4"
		'd5f7731b-f639-404a-89d0-e46186e22c8d' = "S10"
		'ff85ef31-da5b-4eac-95dd-a69d6f97b18a' = "S15"
		'88ea9228-457a-4091-adc9-ad5194f30b6e' = "S20"
		'5b1db88a-8596-4002-8052-347947c26940' = "S30"
		'7660b45b-b29d-49cb-b816-59f30fbab011' = "P4"
		'817007fd-a077-477f-bc01-b876f27205fd' = "P6"
		'e554b6bc-96cd-4938-a5b5-0da990278519' = "P10"
		'cdc0f53a-62a9-4472-a06c-e99a23b02907' = "P15"
		'b9cb2d1a-84c2-4275-aa8b-70d2145d59aa' = "P20"
		'06bde724-9f94-43c0-84c3-d0fc54538369' = "P30"
		'7ba084ec-ef9c-4d64-a179-7732c6cb5e28' = "ActualStandardDiskSize"
		'daef389a-06e5-4684-a7f7-8813d9f792d5' = "ActualPremiumDiskSize"
		'75d4b707-1027-4403-9986-6ec7c05579c8' = "ActualStandardSnapshotSize"
		'5ca1cbb9-6f14-4e76-8be8-1ca91547965e' = "ActualPremiumSnapshotSize"
		'5d76e09f-4567-452a-94cc-7d1f097761f0' = "S4 (Deprecated)"
		'dc9fc6a9-0782-432a-b8dc-978130457494' = "S6 (Deprecated)"
		'e5572fce-9f58-49d7-840c-b168c0f01fff' = "S10 (Deprecated)"
		'9a8caedd-1195-4cd5-80b4-a4c22f9302b8' = "S15 (Deprecated)"
		'5938f8da-0ecd-4c48-8d5a-c7c6c23546be' = "S20 (Deprecated)"
		'7705a158-bd8b-4b2b-b4c2-0782343b81e6' = "S30 (Deprecated)"
		'5c105f5f-cbdf-435c-b49b-3c7174856dcc' = "P4 (Deprecated)"
		'518b412b-1927-4f25-985f-4aea24e55c4f' = "P6 (Deprecated)"
		'5cfb1fed-0902-49e3-8217-9add946fd624' = "P10 (Deprecated)"
		'8de91c94-f740-4d9a-b665-bd5974fa08d4' = "P15 (Deprecated)"
		'c7e7839c-293b-4761-ae4c-848eda91130b' = "P20 (Deprecated)"
		'9f502103-adf4-4488-b494-456c95d23a9f' = "P30 (Deprecated)"
		'8a409390-1913-40ae-917b-08d0f16f3c38' = "ActualStandardDiskSize (Deprecated)"
		'1273b16f-8458-4c34-8ce2-a515de551ef6' = "ActualPremiumDiskSize (Deprecated)"
		'89009682-df7f-44fe-aeb1-63fba3ddbf4c' = "ActualStandardSnapshotSize (Deprecated)"
		'95b0c03f-8a82-4524-8961-ccfbf575f536' = "ActualPremiumSnapshotSize (Deprecated)"
	    'CBCFEF9A-B91F-4597-A4D3-01FE334BED82' = 'DatabaseSizeHourSqlMeter'
		'E6D8CFCD-7734-495E-B1CC-5AB0B9C24BD3' = 'DatabaseSizeHourMySqlMeter'
		'EBF13B9F-B3EA-46FE-BF54-396E93D48AB4' = 'Key Vault transactions'
		'2C354225-B2FE-42E5-AD89-14F0EA302C87' = 'Advanced keys transactions'
		'190C935E-9ADA-48FF-9AB8-56EA1CF9ADAA' = 'App Service'
		'67CC4AFC-0691-48E1-A4B8-D744D1FEDBDE' = 'Functions Requests'
		'D1D04836-075C-4F27-BF65-0A1130EC60ED' = 'Functions - Compute'
		'957E9F36-2C14-45A1-B6A1-1723EF71A01D' = 'Shared App Service Hours'
		'539CDEC7-B4F5-49F6-AAC4-1F15CFF0EDA9' = 'Free App Service Hours'
		'88039D51-A206-3A89-E9DE-C5117E2D10A6' = 'Small Standard App Service Hours'
		'83A2A13E-4788-78DD-5D55-2831B68ED825' = 'Medium Standard App Service Hours'
		'1083B9DB-E9BB-24BE-A5E9-D6FDD0DDEFE6' = 'Large Standard App Service Hours'
		'Custom Worker Tiers' = 'Custom Worker Tiers'
		'264ACB47-AD38-47F8-ADD3-47F01DC4F473' = 'SNI SSL'
		'60B42D72-DC1C-472C-9895-6C516277EDB4' = 'IP SSL'
		'73215A6C-FA54-4284-B9C1-7E8EC871CC5B' = 'Web Process'
		'5887D39B-0253-4E12-83C7-03E1A93DFFD9' = 'External Egress Bandwidth'

    }
	$ratecardmapping = @{}
	$rateCardObj = New-Object -TypeName System.Object
	$rateCardObj | Add-Member -Name MeterName -MemberType NoteProperty -Value "BlockBlobCapacity"
	$rateCardObj | Add-Member -Name MeterId -MemberType NoteProperty -Value "8a913f38-33b4-4772-9488-e89522fc09e5"
	$rateCardObj | Add-Member -Name Units -MemberType NoteProperty -Value "1 GB/Hr"
	$rateCardObj | Add-Member -Name OpenRate -MemberType NoteProperty -Value "0.0000083333"
	$ratecardmapping.Add("BlockBlobCapacity",$rateCardObj)
	$rateCardObj = New-Object -TypeName System.Object
	$rateCardObj | Add-Member -Name MeterName -MemberType NoteProperty -Value "Windows VM Size Hours"
	$rateCardObj | Add-Member -Name MeterId -MemberType NoteProperty -Value "fb8c0713-ea20-40bf-901f-5560fd3f6330"
	$rateCardObj | Add-Member -Name Units -MemberType NoteProperty -Value "1 Core Hour"
	$rateCardObj | Add-Member -Name OpenRate -MemberType NoteProperty -Value "0.046"
	$ratecardmapping.Add("Windows VM Size Hours",$rateCardObj)
	$rateCardObj = New-Object -TypeName System.Object
	$rateCardObj | Add-Member -Name MeterName -MemberType NoteProperty -Value "Base VM Size Hours"
	$rateCardObj | Add-Member -Name MeterId -MemberType NoteProperty -Value "fab6eb84-500b-4a09-a8ca-7358f8bbaea5"
	$rateCardObj | Add-Member -Name Units -MemberType NoteProperty -Value "1 Core Hour"
	$rateCardObj | Add-Member -Name OpenRate -MemberType NoteProperty -Value "0.008"
	$ratecardmapping.Add("Base VM Size Hours",$rateCardObj)
	$rateCardObj = New-Object -TypeName System.Object
	$rateCardObj | Add-Member -Name MeterName -MemberType NoteProperty -Value "VM Size Hours"
	$rateCardObj | Add-Member -Name MeterId -MemberType NoteProperty -Value "6dab500f-a4fd-49c4-956d-229bb9c8c793"
	$rateCardObj | Add-Member -Name Units -MemberType NoteProperty -Value "1 Core Hour"
	$rateCardObj | Add-Member -Name OpenRate -MemberType NoteProperty -Value "0.008"
	$ratecardmapping.Add("VM Size Hours",$rateCardObj)
    if (!$TenantUsage) {
        $uri = $armEndpoint + '/subscriptions/{0}/providers/Microsoft.Commerce/subscriberUsageAggregates?api-version=2015-06-01-preview&reportedstartTime={1}&reportedEndTime={2}&showDetails=true&aggregationGranularity={3}' -f $defaultProviderSub, $StartTime1, $EndTime1, $Granularity1 
    }
    else {
        $uri = $armEndpoint + '/subscriptions/{0}/providers/Microsoft.Commerce/UsageAggregates?api-version=2015-06-01-preview&reportedstartTime={1:s}&reportedEndTime={2:s}&showDetails=true&aggregationGranularity={3}' -f $defaultProviderSub, $StartTime1, $EndTime1, $Granularity1
    }
    $usageSummary = @()
    $processCount=0
    #Call REST api an loop thru each record returned
	Do {
		Write-Debug "uri : $uri"
		$result = Invoke-RestMethod -Method GET -Uri $uri  -Headers $headers -ErrorVariable RestError
		if ($RestError) {
			Write-Host -ForegroundColor Red "Error calling API.."
			return
		}
		$uri = $result.NextLink
		$count = $result.value.Count
		$TotalRecords += $count
		$result.value  | ForEach-Object {
			$processCount += 1
			Write-Progress -Activity "Records received # $processCount ..."

			$record = New-Object -TypeName System.Object
			$resourceInfo = ($_.Properties.InstanceData |ConvertFrom-Json).'Microsoft.Resources'
			$resourceText = $resourceInfo.resourceUri.Replace('\', '/')
			$metersubscription = $resourceText.Split('/')[2]
			$resourceType = $resourceText.Split('/')[7]
			$resourceName = $resourceText.Split('/')[8]

			#Get the attached user tenant for meter
			$tenant = CreateEmptyTenantObject
			if ($currentSubscriptionList.ContainsKey($metersubscription)){
				$tenant = $currentSubscriptionList[$metersubscription]
			}

			#Populate all required tenant details
			if([string]::IsNullOrEmpty($tenant.Owner)) {
				$record | Add-Member -Name Tenant -MemberType NoteProperty -Value "mystery-user"
			} else {
				$record | Add-Member -Name Tenant -MemberType NoteProperty -Value $tenant.Owner
			}
			if([string]::IsNullOrEmpty($tenant.DisplayName)) {
				$record | Add-Member -Name TenantSubscriptionName -MemberType NoteProperty -Value "Mystery Subscription"
			} else {
				$record | Add-Member -Name TenantSubscriptionName -MemberType NoteProperty -Value $tenant.DisplayName
			}
			if([string]::IsNullOrEmpty($tenant.State)) {
				$record | Add-Member -Name TenantSubscriptionState -MemberType NoteProperty -Value "Unknown"
			} else {
				$record | Add-Member -Name TenantSubscriptionState -MemberType NoteProperty -Value $tenant.State
			}

			$record | Add-Member -Name subscription -MemberType NoteProperty -Value $metersubscription
			$record | Add-Member -Name location -MemberType NoteProperty -Value ([string]::Format("{0}.{1}",$resourceInfo.location,$AzureStackDomain1))
			$record | Add-Member -Name CloudName -MemberType NoteProperty -Value $CloudName1
			$record | Add-Member -Name resourceType -MemberType NoteProperty -Value $resourceType
			$record | Add-Member -Name resourceName -MemberType NoteProperty -Value $resourceName
			$record | Add-Member -Name UsageStartTime -MemberType NoteProperty -Value $_.Properties.UsageStartTime
			$record | Add-Member -Name UsageEndTime -MemberType NoteProperty -Value $_.Properties.UsageEndTime
			$record | Add-Member -Name Id -MemberType NoteProperty -Value $_.id
			$record | Add-Member -Name Name -MemberType NoteProperty -Value $_.Name
			$record | Add-Member -Name Type -MemberType NoteProperty -Value $_.Type
			$record | Add-Member -Name MeterId -MemberType NoteProperty -Value $_.Properties.MeterId
			$record | Add-Member -Name Quantity -MemberType NoteProperty -Value $_.Properties.Quantity
			$record | Add-Member -Name additionalInfo -MemberType NoteProperty -Value $resourceInfo.additionalInfo
			$record | Add-Member -Name tags -MemberType NoteProperty -Value $resourceInfo.tags
			$record | Add-Member -Name resourceUri -MemberType NoteProperty -Value $resourceText

			#Check to see whether this resource's meterId is known
			if ($azsmeters.ContainsKey($_.Properties.MeterId)) {
				$record | Add-Member -Name MeterName -MemberType NoteProperty -Value $azsmeters[$_.Properties.MeterId]
				#Check to see whether ratecard info for this meter exist
				if($ratecardmapping.ContainsKey($azsmeters[$_.Properties.MeterId])) {
					$rateCardObj = $ratecardmapping[$azsmeters[$_.Properties.MeterId]]
					$record | Add-Member -Name RateCardMeterId -MemberType NoteProperty -Value $rateCardObj.MeterId
					$record | Add-Member -Name MeterUnit -MemberType NoteProperty -Value $rateCardObj.Units
					$record | Add-Member -Name OpenRate -MemberType NoteProperty -Value $rateCardObj.OpenRate
				} else {
					$record | Add-Member -Name RateCardMeterId -MemberType NoteProperty -Value "Unknown"
					$record | Add-Member -Name MeterUnit -MemberType NoteProperty -Value "Unknown"
					$record | Add-Member -Name OpenRate -MemberType NoteProperty -Value "0"
				}
			} else {
				$record | Add-Member -Name MeterName -MemberType NoteProperty -Value "Unknown"
				$record | Add-Member -Name RateCardMeterId -MemberType NoteProperty -Value "Unknown"
				$record | Add-Member -Name MeterUnit -MemberType NoteProperty -Value "Unknown"
				$record | Add-Member -Name OpenRate -MemberType NoteProperty -Value "0"
			}
            
			$usageSummary += $record
		}
	}
	While ($result.NextLink -ne $null)
    
	#Save the output to JSON file
    if (!$TenantUsage) 
    {
		$jsonFile = "$Region-$AzureStackDomain1-$Granularity1-UsageSummary.json"
    } else 
    {
		$jsonFile = "$Region-$AzureStackDomain1-$Granularity1-TenantUsageSummary.json"
    }
    #If output file already exists (from previous runs) delete it
    if (Test-Path -Path $jsonFile -ErrorAction SilentlyContinue) {
    Write-Host -ForegroundColor Yellow "$jsonFile alreday exists. Deleting previous file"
    Remove-Item -Path $jsonFile -Force
   }
    New-Item -Path $jsonFile -ItemType File | Out-Null
	ConvertTo-Json -InputObject $usageSummary | Out-File $jsonFile

    Write-Host -ForegroundColor Green "Complete - $TotalRecords Usage records written to $jsonFile"
} # end of function Export-AzureStackUsage

#main code body
#Get AzureStack admin user credentials
if(!$Creds) 
{
	$aadCred = Get-Credential -Message "Enter AzureStack admin user credentials for $AzureStackRegion.$AzureStackDomain"
} 
else 
{
	$aadCred = $Creds
}

#Login to Azure Stack
$api = "adminmanagement"
$AzureStackAdminEndPoint = 'https://{0}.{1}.{2}' -f $api, $AzureStackRegion, $AzureStackDomain
Add-AzureRMEnvironment -Name $AzureStackCloudName -ArmEndpoint $AzureStackAdminEndPoint
Login-AzureRmAccount -EnvironmentName $AzureStackCloudName -Credential $aadCred

#convert datetime string to format required
$startTimeString = ($StartTime).ToString("yyyy-MM-ddT00:00:00+00:00Z")
$startTimeString= $startTimeString -replace ":","%3a"
$startTimeString= $startTimeString -replace "\+","%2b"
Write-Debug "Formatted StartTime is $startTimeString"

$endTimeString = ($EndTime).ToString("yyyy-MM-ddT00:00:00+00:00Z")
$endTimeString = $endTimeString -replace ":","%3a"
$endTimeString = $endTimeString -replace "\+","%2b"
Write-Debug "Formatted EndTime is $endTimeString"

# Make call to get usage data
if($TenantUsage) {
   Export-AzureStackUsage -StartTime $startTimeString -EndTime $endTimeString -AzureStackDomain $AzureStackDomain `
	-AADDomain $aadDomain  -Region $AzureStackRegion -Credential $aadCred -Granularity $Granularity `
	-CloudName1 $AzureStackCloudName -TenantUsage
}
else {
   Export-AzureStackUsage -StartTime $startTimeString -EndTime $endTimeString -AzureStackDomain $AzureStackDomain `
	-AADDomain $aadDomain  -Region $AzureStackRegion -Credential $aadCred -Granularity $Granularity `
	-CloudName1 $AzureStackCloudName
}
