# composability
What does the project do?

We want to generate logical facts about VPC configurations and use that with network semantic rules and security policy rules to verify whether the given VPC configurations and the resources within the VPC satisfy the policy rules.
We use Prolog to represent the facts and rules.
This shell script walks through VPCs in an AWS account and creates Prolog facts about the VPC configuration and the configuration of resources in the VPC, such as compute units, RDS instances, and the associated SecurityGroups.

How to use the shellscript?
1. Download and install the latest version of AWS cli.
2. Install jq 
3. Initialize access key and secret access key
4. Then invoke the program as: ./mapSecurity.sh <AWS Region> <Outputfle name prefix>
us-west-2 is the default region. outputfile_<ddmmyyyy>_<vpd-id>.pl is the default
<ddmmyyyy> suffix will be added to the outputfile name if one is given.


Once we have the Prolog output file with facts and rules, this can be run in SwiProlog as 'swipl <outputfile name>' and query the knowledge of facts 
to see if a goal is satisfied. Swipl can be installed with instructions from https://gist.github.com/norswap/39805b733e68c4df119375d4c7a96da4.

For example, to query compute instances with unencrypted EBS volumes:
? unencrypted(X). 
