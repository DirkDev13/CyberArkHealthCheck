# CyberArkHealthCheck

**Description:**  
A Project to setup Health Checks of the CyberArk Components. It consists of 3 parts:
- The Vault-HealthCheck which is a script that pulls the Vault System Data and recording safe information, encodes and pushes the data to an account object in CyberArk.
- The Component-HealthCheck which is a script that pulls the System data of components, encodes and pushes the data to an account object in CyberArk. It pulls data for the following components the following components:
    - PVWA
    - CPM
    - PSM
    - AAM
    - Backup/ PAReplicate
- The HCReport that pulls all the data and builts and HTML report.

**Version**
This is Version 1.0

## Table of Contents
- [Requirements](#Requirements)
- [Installation](#installation)
    - [Vault](#Vault)
    - [Components](#Components)
    - [HCReport](#HCReport)
- [Usage](#usage)
- [Example](#Example)
- [Author](#Author)

## Requirements
Here is the list of requirements
- PACLI V14.2
- Powershell 5.0 or above
- psPAS V6.4.85
- PoShPACLI V2.1.27
- 1 EPV User License 
- A CyberArk user with the following permissions
    - Add User
    - Add Safe
    - Add Safe Members
    - Add Group Members

## Setup
Below is the instructions on how to setup the 3 parts of the Health Check

### HCReport
The HCReport Setup consits of 6 Parts
1. Setting up the Required PowerShell Modules
2. Creating a Credential File for the Vault user that will pull the report data from the Accounts
3. Creating a configuration file for the report
4. Setting up the Health Check Accounts for each server in the Vault
5. Creating a specific Vault User to run the Health Checks (Will consume an EPV license)
6. Setup of the HTML Report for the environment

There is a setup script located in the Setup folder that can be run to perform all the above steps.

### Vault
The Vault Setup consits of 5 parts
1. Setting up the Required PowerShell Modules
2. Creating the Credential file that will be used to logon to the Vault
3. Configuring PACLI
4. Validating that there is an HCAccount onboarded for this Vault Server to push data to
5. Setting up the scheduled task to pull and push data once a day at 5am.

There is an setup script located in the Setup folder that can be run to perform all the above steps.

### Components
The Component Setup consits of 5 parts
1. Setting up the Required PowerShell Modules
2. Creating the Credential file that will be used to logon to the Vault
3. Creating an configuration file for the environment
4. Validating that there is an HCAccount onboarded for this Vault Server to push data to
5. Setting up the scheduled task to pull and push data once a day at 5am.

There is an setup script located in the Setup folder that can be run to perform all the above steps
NB! When you do the setup make sure to create place the Component-HealthCheck folder in the C:\Scripts location, otherwise you need to update the scheduled task xml. The following parameter need to be updated in the scheduled task xml
- Arguments
- Working Directory

## Usage
Run the HCReport.ps1 script once everything has been setup to generate a report.
It will automatically open and it will save a copy to the Reports folder.

## Example
There is an example Report in the main folder 

## Author
Name: Dirk de Klerk
