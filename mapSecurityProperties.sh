#!/bin/bash
# Some variables and cosntants to use in the script
REGION=us-west-2
echo $REGION
OUTPUTFILE=outputfile
SEPARATOR="_"
VPC_ID=
ACCOUNT=aws_account

## Fail on any error
trap 'echo "ERROR: the previous command failed, bailing out"; exit 1' ERR


# Function to show help 
function showHelp() 
{
	echo
	echo "To gather security proproperty of a given VPC: $0 --region <AWS Region Name>  --vpc_id=<vpc_id> --outputfile=<prolog output file>"
	echo
	echo "us-east-1 is the default for region, all vpcs is the default when no specific vpc_id is provided. The default filename is outputfile.pl"
	echo 
}

openfile()
{
   # Get today's date
   # $1 is VPC ID

   DD=$(date +%d)
   MM=$(date +%m)
   YY=$(date +%y)
   id=$1
   id=`echo "${id//\"}"`
   FILENAME="$OUTPUTFILE$SEPARATOR$DD$MM$YY$SEPARATOR$id.pl"
   echo "Facts and Rules will be written to: $FILENAME"
   
   echo ":- use_module('cidr.pl')." > "$FILENAME"
   echo ":- use_module(library(clpb))." >> "$FILENAME"
   echo ":- use_module(library(prolog_stack))." >> "$FILENAME"
   echo ":- consult('properties.pl')." >> "$FILENAME"
   echo ":- discontiguous compute/5." >> "$FILENAME"
   echo ":- discontiguous placement/5." >> "$FILENAME"
   echo ":- discontiguous vpc/4." >> "$FILENAME"
   echo ":- discontiguous secgroup/9." >> "$FILENAME"
   echo ":- discontiguous nacl/9." >> "$FILENAME"
   echo ":- discontiguous nacl_association/4." >> "$FILENAME"
   echo ":- discontiguous rds/3." >> "$FILENAME"
   echo ":- discontiguous secgrp_association/4." >> "$FILENAME"
   echo ":- discontiguous subnet/4." >> "$FILENAME"
   echo ":- discontiguous alb/2." >> "$FILENAME"

   echo "/**" >> "$FILENAME"
   echo "**" >> "$FILENAME"
   echo "* VPC Configuration Information" >> "$FILENAME"
   echo "**" >> "$FILENAME"
   echo "*/" >> "$FILENAME"
}
printCommentToFile() {
   echo "/**" >> "$FILENAME"
   echo "**" >> "$FILENAME"
   echo "* $1 Configuration Information" >> "$FILENAME"
   echo "* No of $1s: $2" >> "$FILENAME"
   echo "**" >> "$FILENAME"
   echo "*/" >> "$FILENAME"
}


printElapsedTime(){
        let elapsedApi=$2-$1
        let elapsedProcessing=$4-$1
        echo "$3 - elapsedtime: $elapsedApi seconds."
        echo "$5 - elapsedtime: $elapsedProcessing seconds."
        echo "/**" >> "$FILENAME"
        echo "**" >> "$FILENAME"
        echo "* $3 - elapsedtime: $elapsedApi seconds." >> "$FILENAME"
        echo "* $5 - elapsedtime: $elapsedProcessing." >> "$FILENAME"
        echo "**" >> "$FILENAME"
        echo "*/" >> "$FILENAME"
}

processVPC() {
        echo "Args passed: $#"    
        vpc_id=$1
        cidr=$2
        echo "VPC id: $vpc_id"

        # Open a file for writing the Prolog facts
        openfile $vpc_id

        # Add the vpc entry
        echo "vpc($vpc_id, $cidr, $ACCOUNT, $REGION)." >> "$FILENAME"

        # Get subnet information
        start_vpc=`date +%s`
        apiStart=`date +%s`
        echo -e "Fetching subnets for VPC: $vpc_id\n"
        filter="Name=vpc-id,Values=$vpc_id"
        subnets=`aws ec2 describe-subnets --filters $filter`
        apiEnd=`date +%s`
        subnets_info=`jq '.[]' <<< $subnets`
        # Look for subnet information returned in an array format
        let END1=`jq length <<< $subnets_info`-1
        printCommentToFile "Subnet" $((END1+1))
        echo "Number of subnets: $((END1+1))"
        for i in $(eval echo "{0..$END1}")
        do
           subnetentry=$(jq '.['$i']' <<< $subnets_info)
           subnet_id=`jq '.SubnetId?' <<< $subnetentry`
           if [ "$subnet_id" = "null" ]
           then
               break
           fi
           vpc_id=`jq '.VpcId?' <<< $subnetentry`
           publicsubnet=`jq '.MapPublicIpOnLaunch?' <<< $subnetentry`
           cidr=`jq '.CidrBlock?' <<< $subnetentry`
           subnet_type=private
           if [ "$publicsubnet" = "true" ]
           then
               subnet_type=public
           fi
           cidr=`echo "${cidr//\"}"`
           cidr=`echo "ip(${cidr//./,})"`
           echo "subnet($vpc_id, $subnet_id, $cidr, $subnet_type)." >> "$FILENAME"
        done
        processingEnd=`date +%s`
        printElapsedTime $apiStart $apiEnd "Subnet api" $processingEnd "Subnet processing"

        # Get NACL info
        echo -e "Fetching NACLS information for VPC: $vpc_id\n"
        apiStart=`date +%s`
        nacl_info=`aws ec2 describe-network-acls --filter $filter`
        apiEnd=`date +%s`
        nacls=`jq '.NetworkAcls?' <<< $nacl_info`
        
        # Get network association entries
        nacl_id=null
        let END2=`jq length <<< $nacls`-1
        printCommentToFile "NACL" $((END2+1))
        echo "Number of NACLs: $((END2+1))"
        for i in $(eval echo "{0..$END2}")
        do
          # Get network association rules
          assoc_info=$(jq '.['$i'] .Associations?' <<< $nacls)
          if [ "$assoc_info" != 'null' ]
          then
             # Get the acl id and subnet id and create facts
             let END3=`jq length <<< $assoc_info`-1
             for j in $(eval echo "{0..$END3}")
             do
                assoc_id=$(jq '.['$j'] .NetworkAclAssociationId?' <<< $assoc_info)
                if [ "$assoc_id" == 'null' ]
                then
                   break
                fi
                nacl_id=$(jq '.['$j'] .NetworkAclId?' <<< $assoc_info)
                subnet_id=$(jq '.['$j'] .SubnetId?' <<< $assoc_info)

                # write the NACL association as a fact
                # assoc_id=`echo "${assoc_id//\"}"`
                # nacl_id=`echo "${nacl_id//\"}"`
                # subnet_id=`echo "${subnet_id//\"}"`
                if [ "$nacl_id" != null ]
                then
                    echo "nacl_association($vpc_id, $assoc_id, $nacl_id, $subnet_id)." >> "$FILENAME"
                fi
             done
          fi
          # Now process the NACL Entries
          nacl_entries=$(jq '.['$i'] .Entries?' <<< $nacls) 
          if [ "$nacl_entries" != 'null' ] && [ "$nacl_entries" != '[]' ]
          then
              # Process NACL entries
              let END4=`jq length <<< $nacl_entries`-1
              for j in $(eval echo "{0..$END4}")
              do
                nacl_entry=$(jq '.['$j']' <<< $nacl_entries)
                if [ "$nacl_entry" != 'null' ] && [ "$nacl_entry" != '[]' ]
                then
                   # Extract fields from the nack entry
                   cidr=`jq '.CidrBlock?' <<< $nacl_entry`
                   proto=`jq '.Protocol?' <<< $nacl_entry`
                   egress=`jq '.Egress?' <<< $nacl_entry`
                   action=`jq '.RuleAction?' <<< $nacl_entry`
                   rno=`jq '.RuleNumber?' <<< $nacl_entry`
                   direction=ingress
                   if [ "$egress" = "true" ]
                   then
                         direction=egress
                   fi

                    # If there is a port range parse them out
                    fromPort=-1
                    toPort=-1
                    portRange=`jq '.PortRange?' <<< $nacl_entry`
                    if [ "$portRange" != "null" ] 
                    then
                       fromPort=`jq '.From?' <<< $portRange`
                       toPort=`jq '.To?' <<< $portRange`
                       fromPort=`echo "${fromPort//\"}"`
                       toPort=`echo "${toPort//\"}"`
                   fi
                   proto=`echo "${proto//\"}"`
                   cidr=`echo "${cidr//\"}"`
                   cidr=`echo "ip(${cidr//./,})"`
                   action=`echo "${action//\"}"`
                   echo "nacl($vpc_id, $nacl_id, $direction, $rno, $proto, $fromPort, $toPort, $cidr, $action)." >> "$FILENAME" 
                else
                   break
                fi
              done
          else
              break
          fi
        done
        processingEnd=`date +%s`
        printElapsedTime $apiStart $apiEnd "NACL api" $processingEnd "NACL processing"

        # Process Security Groups
        echo -e "Processing Security Groups in VPC: $vpc_id\n"
        
        apiStart=`date +%s`
        sg_info=`aws ec2 describe-security-groups --filter $filter`
        apiEnd=`date +%s`
        sgs_array=`jq '.SecurityGroups?' <<< $sg_info`
        let END5=`jq length <<< $sgs_array`-1
        printCommentToFile "SecurityGroup" $((END5+1))
        echo "Number of SGs: $((END5+1))"
        for i in $(eval echo "{0..$END5}")
        do
           sg_entry=$(jq '.['$i']' <<< $sgs_array)
           # echo $sg_entry
           if [ "$sg_entry" = "null" ]
           then
               break
           fi

           # Extract the fields
           sgName=`jq '.GroupName?' <<< $sg_entry`
           #sgName=`echo "${sgName//\"}"`
           sgName=`echo "$sgName" | awk '{print tolower($0)}'`
           thisSgGroupId=`jq '.GroupId?' <<< $sg_entry`

           # Parse each ingress entry
           for j in {0..50}
           do
              # These are the ingress rules
              ingress_entry=$(jq '.IpPermissions | .['$j']' <<< $sg_entry)
              #echo $ingress_entry
              if [ "$ingress_entry" = "null" ]
              then
                 break
              fi
 
              # For each entry get the properties
              fromPort=`jq '.FromPort?' <<< $ingress_entry`
              ipProto=`jq '.IpProtocol?' <<< $ingress_entry`
              ipRanges=`jq '.IpRanges?' <<< $ingress_entry`
              cidrIp=null
              desc=null
              ipv6Ranges=`jq '.Ipv6Ranges?' <<< $ingress_entry`
              toPort=`jq '.ToPort?' <<< $ingress_entry`
              
              # Add the entry to the output file after removing the double quotes
              fromPort=`echo "${fromPort//\"}"`
              ipProto=`echo "${ipProto//\"}"`
	      toPort=`echo "${toPort//\"}"`
              dest=null

              if [ "$ipRanges" != "[]" ]
              then
                  let NUMIPS=`jq length <<< $ipRanges`-1
                  for n in $(eval echo "{0..$NUMIPS}")
                  do
                     cidrIp=$(jq '.['$n'] | .CidrIp?' <<< $ipRanges)
                     desc=$(jq '.['$n'] | .Description?' <<< $ipRanges)
                     if [ "$cidrIp" != "null" ]
	             then
		         dest=`echo "${cidrIp//\"}"`
                         dest=`echo "ip(${dest//./,})"`
                         echo "secgroup($sgName, $thisSgGroupId, "ingress", $j, $ipProto, $fromPort, $toPort, $dest, $desc)." >> "$FILENAME"
                     fi
                   done
              fi

              # if the destination if security group(s), process the array
              userIdGroups=`jq '.UserIdGroupPairs?' <<< $ingress_entry`
              sgGroupId=null
              if [ "$userIdGroups" != "[]" ]
              then
                  let NUMSGIDS=`jq length <<< $userIdGroups`-1
                  for n in $(eval echo "{0..$NUMSGIDS}")
                  do
                      sgGroupId=$(jq '.['$n'] | .GroupId?' <<< $userIdGroups)
                      desc=$(jq '.['$n'] | .Description?' <<< $userIdGroups)
                      if [ "$sgGroupId" != "null" ]
                      then
                         dest=$sgGroupId
                         echo "secgroup($sgName, $thisSgGroupId, "ingress", $j, $ipProto, $fromPort, $toPort, $dest, $desc)." >> "$FILENAME"
                      fi
                  done
              fi
            done

            # Parse each egress entries
            for k in {0..50}
            do
              # These are the egress rules
              egress_entry=$(jq '.IpPermissionsEgress | .['$k']' <<< $sg_entry)
              if [ "$egress_entry" = "null" ]
              then
                 break
              fi

              # For each entry get the properties
              fromPort=`jq '.FromPort?' <<< $egress_entry`
              ipProto=`jq '.IpProtocol?' <<< $egress_entry`
              ipRanges=`jq '.IpRanges?' <<< $egress_entry`
              cidrIp=null
              desc=null
              ipv6Ranges=`jq '.Ipv6Ranges?' <<< $egress_entry`
              toPort=`jq '.ToPort?' <<< $egress_entry`
              

              # Add the entry to the output file after removing the double quotes
              fromPort=`echo "${fromPort//\"}"`
              ipProto=`echo "${ipProto//\"}"`
	      toPort=`echo "${toPort//\"}"`
              dest=null
              # If the FromPort and ToPort are null, assign default values
              if [ "$fromPort" = null ]
              then
                 fromPort=0
              fi
              if [ "$toPort" = null ]
              then
                 toPort=65535
              fi

              if [ "$ipRanges" != "[]" ]
              then
                  let NUMIPS=`jq length <<< $ipRanges`-1
                  for n in $(eval echo "{0..$NUMIPS}")
                  do
                     cidrIp=$(jq '.['$n'] | .CidrIp?' <<< $ipRanges)
                     desc=$(jq '.['$n'] | .Description?' <<< $ipRanges)
                     if [ "$cidrIp" != "null" ]
	             then
		         dest=`echo "${cidrIp//\"}"`
                         dest=`echo "ip(${dest//./,})"`
                         echo "secgroup($sgName, $thisSgGroupId, "egress", $k, $ipProto, $fromPort, $toPort, $dest, $desc)." >> "$FILENAME"
                     fi
                   done
              fi
              # if the destination if security group(s), process the array
              userIdGroups=`jq '.UserIdGroupPairs?' <<< $egress_entry`
              sgGroupId=null
              if [ "$userIdGroups" != "[]" ]
              then
                  let NUMSGIDS=`jq length <<< $userIdGroups`-1
                  for n in $(eval echo "{0..$NUMSGIDS}")
                  do
                      sgGroupId=$(jq '.['$n'] | .GroupId?' <<< $userIdGroups)
                      desc=$(jq '.['$n'] | .Description?' <<< $userIdGroups)
                      if [ "$sgGroupId" != "null" ]
                      then
                         dest=$sgGroupId
                         echo "secgroup($sgName, $thisSgGroupId, "egress", $k, $ipProto, $fromPort, $toPort, $dest, $desc)." >> "$FILENAME"
                      fi
                  done
              fi

           done
       done
       processingEnd=`date +%s`
       printElapsedTime $apiStart $apiEnd "SG - api" $processingEnd "SG processing"

	# Now collect the EC2 instance informaation
        echo -e "Processing information on Compute units in VPC: $vpc_id\n"

        apiStart=`date +%s`
        ec2info=`aws ec2 describe-instances --filter $filter --query 'Reservations[*].Instances[*].{Instance:InstanceId,Subnet:SubnetId, Tags:Tags, SecurityGroups:SecurityGroups, PrivateIpAddress:PrivateIpAddress, PublicIpAddress:PublicIpAddress, InstanceType:InstanceType, BlockDeviceMappings:BlockDeviceMappings}'     --output json`
        apiEnd=`date +%s`
        ec2entry=null
        # Now loop thrugh the array and get individual instance information
        let END6=`jq length <<< $ec2info`-1
        printCommentToFile "EC2" $((END6+1))
        echo "Number of EC2s: $((END6+1))"
        for i in $(eval echo "{0..$END6}")
        do
           ec2entrytl=$(jq '.['$i']' <<< $ec2info)
           if [ "$ec2entrytl" = "null" ]
           then 
             break
           fi

         #Sometimes AWS returns the array incorrectly, combining multiple instanceids in an array within a array element
          innerarrayLen=`jq length <<< $ec2entrytl`
          let END7=$innerarrayLen-1
          for n in $(eval echo "{0..$END7}")
          do
          if [ "$innerarrayLen" == 1 ]
          then
             ec2entry=`jq '.[]' <<< $ec2entrytl`
          else
             ec2entry=$(jq '.['$n']' <<< $ec2entrytl)
         fi

         # Get EC2 attributes
         instanceId=`jq '.Instance?' <<< $ec2entry`
         subnetId=`jq '.Subnet?' <<< $ec2entry`
         instanceType=`jq '.InstanceType?' <<< $ec2entry`
         type=`echo "${instanceType//./$'_'}" | awk '{print tolower($0)}'`

         # Get tag information, specifically name
         tags=`jq '.Tags?' <<< $ec2entry`
         name=null
         if [ "$tags" != "[]" ]
         then
            let END8=`jq length <<< $tags`-1
            for j in $(eval echo "{0..$END8}")
            do
              key=$(jq '.['$j'] | .Key?' <<< $tags)
              value=$(jq '.['$j'] | .Value?' <<< $tags)
	      key=`echo "${key//\"}"`
              if [ "$key" = "Name" ]
              then
                  name=$value
                  #name=`echo "${name//\"}"`
                  name=`echo "$name" | awk '{print tolower($0)}'`
                  break
              fi
           done
         fi
         # Process Security Group information
         sgs=`jq '.SecurityGroups?' <<< $ec2entry`
         sgsarrayLen=`jq length <<< $sgs`
         let END9=`jq length <<< $sgs`-1
         for k in $(eval echo "{0..$END9}")
         do
           sgentry=$(jq '.['$k']' <<< $sgs)
           if [ -z "$sgentry" ] || [ "$sgentry" == 'null' ]
           then
              break
           fi
           sgName=`jq '.GroupName?' <<< $sgentry`
           sgId=`jq '.GroupId?' <<< $sgentry`
           #sgName=`echo "${sgName//\"}"`
           sgName=`echo "$sgName" | awk '{print tolower($0)}'`
           echo "secgrp_association($name, $instanceId, $sgName, $sgId)." >> "$FILENAME"
        done
        
        # Is the instance public?
        publicAddress=`jq '.PublicIpAddress?' <<< $ec2entry`
        ipType=private
        if [ "$publicAddress" != null ]
        then
           ipType=public
        fi
       
        # Find out if the EBS volumes are encrypted
        # Find the default encryption status
        # defencstatus=`aws ec2 get-ebs-encryption-by-default`
        # echo -e "Fetching EBS volume information for instance: $instanceId\n"
        encrypted=true 
        ebsvols=`jq '.BlockDeviceMappings?' <<< $ec2entry`
        if [ "$ebsvols" != "[]" ]
        then
            let END10=`jq length <<< $ebsvols`-1
            for j in $(eval echo "{0..$END10}")
            do
              volId=`jq '.['$j'].Ebs?.VolumeId?' <<< $ebsvols`
              if [ "$volId" = null ] || [ "$volId" = '[]' ]
              then
                 break
              fi
              
              # Get volume information
              volId=`echo "${volId//\"}"`
              if [[ "$volId" != *"null"* ]]
              then
                  volInfo=`aws ec2 describe-volumes --volume-ids $volId`
                  error=`echo $?`
                  if [ "$error" -ne 0 ]
                  then
                     continue
                  fi
                  if [ "$volInfo" != null ]
                  then
                      flag=`jq '.Volumes? | .[].Encrypted?' <<< $volInfo`
                      # Even if one of the volumes is not encrypted, we will set the property to be unencrypted
                      if [ "$flag" = "false" ]
                      then
                          encrypted=$flag
                      fi
                  fi
              fi
           done
        fi
              
       # Get the encryption status for the volume
       ebsEnc=encrypted_ebs
       if [ "$encrypted" = "false" ]
       then
          ebsEnc=unencrypted
       fi

       # add facts
       echo "compute($name, $instanceId, $ebsEnc, $type, $ipType)." >> "$FILENAME"
       echo "placement($name, $instanceId, compute, $vpc_id, $subnetId)." >> "$FILENAME"
       done
       done
       processingEnd=`date +%s`
       printElapsedTime $apiStart $apiEnd "EC2 - api" $processingEnd "EC2 processing"

       # Get ALB information
       echo -e "Processing information on ALBs in the VPC: $vpc_id\n"
      
       vpcIdWithoutQuotes=`echo "${vpc_id//\"}"`
       apiStart=`date +%s`
       cmd="aws elbv2 describe-load-balancers --query '"LoadBalancers[?VpcId==\`$vpcIdWithoutQuotes\`]"'"
       apiEnd=`date +%s`
       albinfo=`eval $cmd`
       let END11=`jq length <<< $albinfo`-1
       printCommentToFile "ALB" $((END11+1))
       echo "Number of ALBs: $((END11+1))"
       for i in $(eval echo "{0..$END11}")
       do
         albentry=$(jq '.['$i']' <<< $albinfo)
         if [ -z "$albentry" ] || [ "$albentry" == 'null' ]
         then 
           break
         fi

         # Get the ALB name
         albname=`jq '.LoadBalancerName?' <<< $albentry`
	 #albname=`echo "${albname//\"}"`
         albtype=`jq '.Type?' <<< $albentry`
	 albtype=`echo "${albtype//\"}"`

         #Add the fact
         echo "alb($albname, $albtype)." >> "$FILENAME"
        
         dnsname=`jq '.DNSName?' <<< $albentry`
        
         # Get subnet information
         subnets=`jq '.AvailabilityZones??' <<< $albentry`
         # Extract subnet information
         arrayLen=`jq length <<< $subnets`
         let END12=`jq length <<< $subnets`-1
         for j in $(eval echo "{0..$END12}")
         do
           subnetid=$(jq '.['$j'] |.SubnetId' <<< $subnets)
           if [ "$subnetid"  == "null" ]
           then
              break
           fi
           # Add fact
           echo "placement($albname, $dnsname, alb, $vpc_id, $subnetid)." >> "$FILENAME"
           
         done
         
         # Get security group information
         albsgs=`jq '.SecurityGroups?' <<< $albentry`
         
         # Get all security groups
         arrayLen=`jq length <<< $albsgs`
         let END13=`jq length <<< $albsgs`-1
         for j in $(eval echo "{0..$END13}")
         do
           sg=$(jq '.['$j']' <<< $albsgs)
           if [ "$sg" = "null" ]
           then 
             break
           fi
          echo "secgrp_association($albname, $dnsname, null, $sg)." >> "$FILENAME"
         done
       done
       processingEnd=`date +%s`
       printElapsedTime $apiStart $apiEnd "ALB - api" $processingEnd "ALB processing"
 

       # Get RDB detailsInformation
        echo -e "Processing information on RDS instances in VPC: $vpc_id\n"

       apiStart=`date +%s`
       aws rds describe-db-instances > rdsinfo.txt
       apiEnd=`date +%s`
       # Filter the RDs instances by vpc-id            
       rdsinfoarray=$(cat rdsinfo.txt | jq '.DBInstances[] |select (.DBSubnetGroup.VpcId == '$vpc_id')' | jq -n '[inputs]')
       rdsinfoArrayLen=`jq length <<< $rdsinfoaaray`
       let END14=rdsinfoArrayLen-1
       printCommentToFile "RDS" $((END14+1))
       echo "Number of RDSs: $((END14+1))"
       for i in $(eval echo "{0..$END14}")
       do
           rdbentry=$(jq '.['$i']' <<< $rdsinfoarray)
           if [ "$rdbentry" = "null" ]
           then 
             break
           fi
           
           #get instance name
           rdbinstance=`jq '.DBInstanceIdentifier?' <<< $rdbentry`
	   #rdbinstance=`echo "${rdbinstance//\"}"`
           #type
           rdstype=`jq '.Engine?' <<< $rdbentry`

           #encrypted?
           encrypted=`jq '.StorageEncrypted?' <<< $rdbentry`
           encryption="unencrypted"
           if [ "$encrypted" = "true" ]
           then
              encryption="encrypted"
           fi

           # create a fact for the instance
           echo "rds($rdbinstance, $encryption, $rdstype)." >> "$FILENAME"

           #Db resource identifier
           dbresourceid=`jq '.DbiResourceId?' <<< $rdbentry`

           #VPC id. We have already selected rds instances only for this VPC.
           # If these do not match, we have a problem.
           vpcid=`jq '.DBSubnetGroup? | .VpcId?' <<< $rdbentry`
           #Get subnet IDs
           subnets=`jq '.DBSubnetGroup? | .Subnets?' <<< $rdbentry`
           let END15=`jq length <<< $subnets`-1
           for j in $(eval echo "{0..$END15}")
           do
             subnet=$(jq '.['$j']' <<< $subnets)
             if [ "$subnet" = "null" ]
             then 
                break
             fi
             
             # Get the subnet id
             subnetid=`jq '.SubnetIdentifier?' <<< $subnet`

             # Add the palcement fact
             echo "placement($rdbinstance, $dbresourceid, rdms, $vpc_id, $subnetid)." >> "$FILENAME"
          done

          # Get the security group id
          rdb_sgs=`jq '.VpcSecurityGroups?' <<< $rdbentry`
          let END16=`jq length <<< $rdb_sgs`-1
          for j in $(eval echo "{0..$END16}")
          do
            sgentry=$(jq '.['$j']' <<< $rdb_sgs)
            if [ "$sgentry" = "null" ]
            then
               break
            fi
            sgId=`jq '.VpcSecurityGroupId?' <<< $sgentry`
            sgstatus=`jq '.Status?' <<< $sgentry`
            sgstatus=`echo "${sgstatus//\"}"`
            if [ "$sgstatus" = "active" ]
            then
              #Todo - need to covert the id to name
              echo "secgrp_association($rdbinstance, $dbresourceid, null, $sgId)." >> "$FILENAME"
            fi
          done
      done
      processingEnd=`date +%s`
      printElapsedTime $apiStart $apiEnd "RDS - api" $processingEnd "RDS processing"
      end_vpc=`date +%s`
      let elapsed=$end_vpc-$start_vpc
      echo "Elapsed time for VPC: $vpd_id: $elapsed seconds."
}

# Parse input arguments
for i in "$@"
do
case $i in
    -r=*|--region=*)
    REGION="${i#*=}"
    ;;
    -a=*|--aws_account=*)
    ACCOUNT="${i#*=}"
    ;;
    -v=*|--vpc_id=*)
    VPC_ID="${i#*=}"
    ;;
    -o=*|--outputfile=*)
    OUTFILE="${i#*=}"
    shift 
    ;;
    -h|--help)
    showHelp
    exit
    SKIP="${i#*=}"
    shift 
    ;;
    *)
            # unknown option
    ;;
esac
done
echo region=$REGION, vpc_id=$VPC_ID, outputfile=$OUTPUTFILE
if [ -z "$VPC_ID" ] 
then
        # Get VPC Information
        echo -e "Gathering information on all VPCs\n"
        start=`date +%s`
        vpcs_info=`aws ec2 describe-vpcs`
        # Get the number of VPC entries
        let VPCEND=`jq '.Vpcs?' <<< $vpcs_info | jq length`-1
        echo "Number of VPCs: $VPCEND"
        for i in $(eval echo "{0..$VPCEND}")
        do
        vpc_id=`jq '.[] | .['$i'] | .VpcId?' <<< "$vpcs_info"`
        echo $vpc_id
        if [ "$vpc_id" = "null" ]
        then
           break
        fi
        cidr=`jq '.[] | . ['$i'] | .CidrBlock?' <<< "$vpcs_info"`
        cidr=`echo "${cidr//\"}"`
        cidr=`echo "ip(${cidr//./,})"`
        echo -e "Gathering information on VPC: $vpc_id\n"
        
        # Now process information about VPC Resources
        processVPC $vpc_id $cidr
        echo -e "Processing completed. Facts are in $FILENAME\n"
        done
else
        echo -e "Gathering information on VPC: $VPC_ID\n"
        start=`date +%s`
        vpcs_info=`aws ec2 describe-vpcs --vpc-ids $VPC_ID`
        vpc_id=$VPC_ID
        cidr=`jq '.[] | . [0] | .CidrBlock?' <<< "$vpcs_info"`
        cidr=`echo "${cidr//\"}"`
        cidr=`echo "ip(${cidr//./,})"`
        # Now process information about VPC Resources
        processVPC $vpc_id $cidr
        echo -e "Processing completed. Facts are in $FILENAME\n"
fi
end=`date +%s`
let elapsed=$end-$start
echo "Total Elapsed time: $elapsed seconds."
