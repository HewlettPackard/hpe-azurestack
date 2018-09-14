#Get usage data with cost
Tool Exports AzureStack usage data with cost to json file
This tool has been tested on Azure Stack integrated systems connected to Azure

## Prerequisites
*Azure and Azure Stack PowerShell modules on the system where you will run this tool. Refer to [Install PowerShell for Azure Stack](https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-powershell-install)
*Network access to Azure Stack ARM endpoints
*AzureStack Operator credentials

## Procedure
* Install Azure Stack PowerShell modules (if not installed already)
* Launch Windows PowerShell console
* Run this tool (refer to parameter examples in the tool)

##IMPORTANT
The AzureStack resource meter rates used in this tool are generic as published by [Microsoft Azure Stack packaging and pricing](https://azure.microsoft.com/mediahandler/files/resourcefiles/5bc3f30c-cd57-4513-989e-056325eb95e1/Azure-Stack-packaging-and-pricing-datasheet.pdf)
Refer to ratecard specific to your AzureStack deployment.


