# composability
What the project does?
We want to generate logical facts about VPC configurations and use that with network semantic rules and Security Policy rules to verify the given VPC configurations and the resources within it satisfy the policy rules. 
We use Prolog to represent the facts and rules.
This shell script walks through VPCs in an AWS account and creates Prolog facts about the VPC configuration and the configurarion of resources in the VPC such as compute units, RDS instances and the associaated SecurityGroups.
How to use the shellscript?
Download and install the latest version of AWS cli.
Install jq 
Initialize access key and secret access key
Then invoke the program as: ./mapSecurity.sh <AWS Region> <Outputfle name prefix>
us-west-2 is the default region. outputfile_<ddmmyyyy>.plis the default
<ddmmyyyy> suffix will be added to the outputfile name if one is given.
