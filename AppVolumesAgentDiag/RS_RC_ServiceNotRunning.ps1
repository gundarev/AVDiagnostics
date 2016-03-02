# Resolver Script - This script fixes the root cause. It only runs if the Troubleshooter detects the root cause.
# Key cmdlets: 
# -- get-diaginput invokes an interactions and returns the response
# -- write-diagprogress displays a progress string to the user

# --declare parameters
PARAM($serviceName)

Get-DiagInput -Id 
# Your logic to fix the root cause here