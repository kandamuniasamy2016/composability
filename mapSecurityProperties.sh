#!/bin/bash
# Some variables and cosntants to use in the script
REGION=us-east-1
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
	echo "To gather security proproperty of a given VPC: $0 --region <AWS Region Name>  --vpc_id=<vpc id> --outputfile=<prolog output file>"
	echo
	echo "us-east-1 is the default for region, all vpcs is the default when no specific vpc_id is provided. The default filename is outputfile_<today's date>.pl"
	echo 
}

openfile()
{
   # Get today's date
   DD=$(date +%d)
   MM=$(date +%m)
   YY=$(date +%y)
   FILENAME="$OUTPUTFILE$SEPARATOR$DD$MM$YY.pl"
   echo "Facts and Rules will be written to: $FILENAME"
   
   echo ":- use_module('cidr.pl')." > "$FILENAME"
   echo ":- use_module(library(clpb))." >> "$FILENAME"
   echo ":- use_module(library(prolog_stack))." >> "$FILENAME"
   echo ":- consult('properties.pl')." >> "$FILENAME"
   echo ":- discontiguous compute/5." >> "$FILENAME"
   echo ":- discontiguous placement/5." >> "$FILENAME"
   echo ":- discontiguous secgrp_association/4." >> "$FILENAME"
   echo ":- discontiguous placement/5." >> "$FILENAME"
   echo ":- discontiguous vpc/4." >> "$FILENAME"
   echo ":- discontiguous secgroup/9." >> "$FILENAME"
   echo ":- discontiguous nacl/6." >> "$FILENAME"
   echo ":- discontiguous nacl_association/4." >> "$FILENAME"
   echo ":- discontiguous rds/3." >> "$FILENAME"
   echo ":- discontiguous secgrp_association/4." >> "$FILENAME"
   echo ":- discontiguous subnet/4." >> "$FILENAME"

   echo "/**" >> "$FILENAME"
   echo "**" >> "$FILENAME"
   echo "* VPC Configuration Information" >> "$FILENAME"
   echo "**" >> "$FILENAME"
   echo "*/" >> "$FILENAME"
}

processVPC() {
        vpc_id=$1
        echo "VPC id: $vpc_id"

        # Get subnet information
        echo -e "Fetching subnets for VPC: $vpc_id\n"
        filter="Name=vpc-id,Values=$vpc_id"
        subnets_info=`aws ec2 describe-subnets --filters $filter`
        # Look for subnet information returned in an array format
        for i in {0..20}
        do
           subnet_id=$(jq '.[] | .['$i'] | .SubnetId?' <<< $subnets_info)
           if [ "$subnet_id" == "null" ]
           then
               break
           fi
           vpc_id_check=$(jq '.[] | .['$i'] | .VpcId?' <<< $subnets_info)
           publicsubnet=$(jq '.[] | .['$i'] | .MapPublicIpOnLaunch?' <<< $subnets_info)
           cidr=$(jq '.[] | .['$i'] | .CidrBlock?' <<< $subnets_info)
           subnet_type=private
           if [ "$publicsubnet" == "true" ]
           then
               subnet_type=public
           fi
           cidr=`echo "${cidr//\"}"`
           cidr=`echo "ip(${cidr//./,})"`
           echo "subnet($vpc_id, $subnet_id, $cidr, $subnet_type)." >> "$FILENAME"
        done

        # Get NACL info
        echo -e "Fetching NACLs information for VPC: $vpc_id\n"
        nacl_info=`aws ec2 describe-network-acls --filter $filter`

        # Get NACL association entries
        nacl_id=null
        for i in {0..50}
        do
           # Get NACL association rules
           assoc_info=$(jq '.[] | .['$i'] .Associations?' <<< $nacl_info)
           if [ "$assoc_info" == '[]' ] || [ "$assoc_info" == 'null' ]
           then
              break
           fi
           
           # process the NACL association entries
           for  j in {0..20}
           do
              assoc_id=$(jq '.['$j'].NetworkAclAssociationId?' <<< $assoc_info)
              if [ "$assoc_id" == 'null' ]
              then
                break
              fi

              nacl_id=$(jq '.['$j'].NetworkAclId?' <<< $assoc_info)
              subnet_id=$(jq '.['$j'].SubnetId?' <<< $assoc_info)

              # Write the NACL association as a fact
              if [ "$nacl_id" != null ]
              then
                echo "nacl_association($vpc_id, $assoc_id, $nacl_id, $subnet_id)." >> "$FILENAME"
              fi
           done

           # Look for nacl information and create facts
           nacl_entries=$(jq '.[] | .['$i'] .Entries?' <<< $nacl_info)
           if [ "$nacl_entries" == 'null' ] || [ "$nacl_entries" == '[]' ]
           then
             break
           fi
           for j in {0..50}
           do
              nacl_entry=$(jq '.['$j']' <<< $nacl_entries)
              if [ "$nacl_entry" = 'null' ] || [ "$nacl_entry" = '[]' ]
              then
                 break
              fi
           
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
              proto=`echo "${proto//\"}"`
              cidr=`echo "${cidr//\"}"`
              cidr=`echo "ip(${cidr//./,})"`
              action=`echo "${action//\"}"`
              echo "nacl($vpc_id, $direction, $rno, $proto, $cidr, $action)." >> "$FILENAME"          
           done
        done

        # Process Security Groups
        echo -e "Processing Security Groups in VPC: $vpc_id\n"
        echo "/**" >> "$FILENAME"
        echo "**" >> "$FILENAME"
        echo "* SecurityGroups Information" >> "$FILENAME"
        echo "**" >> "$FILENAME"
        echo "*/" >> "$FILENAME"

        sg_info=`aws ec2 describe-security-groups --filter $filter`
        sgs_array=`jq '.SecurityGroups?' <<< $sg_info`
        for i in {0..50}
        do
           sg_entry=$(jq '.['$i']' <<< $sgs_array)
           # echo $sg_entry
           if [ "$sg_entry" = 'null' ]
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
              if [ "$ingress_entry" = 'null' ]
              then
                 break
              fi
 
              # For each entry get the properties
              fromPort=`jq '.FromPort?' <<< $ingress_entry`
              ipProto=`jq '.IpProtocol?' <<< $ingress_entry`
              ipRanges=`jq '.IpRanges?' <<< $ingress_entry`
              cidrIp=null
              desc=null
              if [ "$ipRanges" != '[]' ]
              then
                  cidrIp=`jq '.[0] | .CidrIp?' <<< $ipRanges`
                  desc=`jq '.[0] | .Description?' <<< $ipRanges`
              fi
              ipv6Ranges=`jq '.Ipv6Ranges?' <<< $ingress_entry`
              toPort=`jq '.ToPort?' <<< $ingress_entry`
              
              # Fix this. The follwoing could be an array
              userIdGroups=`jq '.UserIdGroupPairs?' <<< $ingress_entry`
              sgGroupId=null
              if [ "$userIdGroups" != "[]" ]
              then
                  sgGroupId=`jq '.[0] | .GroupId?' <<< $userIdGroups`
              fi

              # Add the entry to the output file after removing the double quotes
              fromPort=`echo "${fromPort//\"}"`
              ipProto=`echo "${ipProto//\"}"`
	      toPort=`echo "${toPort//\"}"`
              dest=null
              if [ "$cidrIp" != "null" ]
	      then
		dest=`echo "${cidrIp//\"}"`
                dest=`echo "ip(${dest//./,})"`
              #echo "cidrIP: $cidrIp, sg: $sgGroupId"
              else
		dest=$sgGroupId
              fi
              echo "secgroup($sgName, $thisSgGroupId, "ingress", $j, $ipProto, $fromPort, $toPort, $dest, $desc)." >> "$FILENAME"
            done

            # Parse each egress entries
            for k in {0..50}
            do
              # These are the egress rules
              egress_entry=$(jq '.IpPermissionsEgress | .['$k']' <<< $sg_entry)
              if [ "$egress_entry" = 'null' ]
              then
                 break
              fi

              # For each entry get the properties
              fromPort=`jq '.FromPort?' <<< $egress_entry`
              ipProto=`jq '.IpProtocol?' <<< $egress_entry`
              ipRanges=`jq '.IpRanges?' <<< $egress_entry`
              cidrIp=null
              desc=null
              if [ "$ipRanges" != "[]" ]
              then
                  cidrIp=`jq '.[0] | .CidrIp?' <<< $ipRanges`
                  desc=`jq '.[0] | .Description?' <<< $ipRanges`
              fi
              ipv6Ranges=`jq '.Ipv6Ranges?' <<< $egress_entry`
              toPort=`jq '.ToPort?' <<< $egress_entry`
              
              # Fix this. The follwoing could be an array
              userIdGroups=`jq '.UserIdGroupPairs?' <<< $egress_entry`
              sgGroupId=null
              if [ "$userIdGroups" != "[]" ]
              then
                  sgGroupId=`jq '.[0] | .GroupId?' <<< $userIdGroups`
              fi

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
              if [ "$cidrIp" != "null" ]
	      then
		dest=`echo "${cidrIp//\"}"`
                dest=`echo "ip(${dest//./,})"`
              else
		dest=$sgGroupId
              fi
	      # desc=`echo "${desc//\"}"`
              echo "secgroup($sgName, $thisSgGroupId, "egress", $k, $ipProto, $fromPort, $toPort, $dest, $desc)." >> "$FILENAME"

           done
       done

	# Now collect the EC2 instance informaation
        echo -e "Processing information on Compute units in VPC: $vpc_id\n"
        echo "/**" >> "$FILENAME"
        echo "**" >> "$FILENAME"
        echo "* Compute (EC2) instances information" >> "$FILENAME"
        echo "**" >> "$FILENAME"
        echo "*/" >> "$FILENAME"

        ec2info=`aws ec2 describe-instances --filter $filter --query 'Reservations[*].Instances[*].{Instance:InstanceId,Subnet:SubnetId, Tags:Tags, SecurityGroups:SecurityGroups, PrivateIpAddress:PrivateIpAddress, PublicIpAddress:PublicIpAddress, InstanceType:InstanceType, BlockDeviceMappings:BlockDeviceMappings}'     --output json`
        ec2entry=null
        # Now loop thrugh the array and get individual instance information
        for i in {0..50}     
        do
           ec2entrytl=$(jq '.['$i']' <<< $ec2info)
           if [ "$ec2entrytl" = 'null' ]
           then 
             break
           fi
          ec2entry=`jq '.[]' <<< $ec2entrytl`

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
            for j in {0..50}
            do
              key=$(jq '.['$j'] | .Key?' <<< $tags)
              value=$(jq '.['$j'] | .Value?' <<< $tags)
	      key=`echo "${key//\"}"`
              if [ "$key" = "Name" ]
              then
                  name=$value
                  name=`echo "${name//\"}"`
                  name=`echo "$name" | awk '{print tolower($0)}'`
                  break
              fi
           done
         fi
         # Process Security Group information
         sgs=`jq '.SecurityGroups?' <<< $ec2entry`
         sgName=null
         if [ "$sgs" != "[]" ]
         then
           sgName=`jq '.[] | .GroupName?' <<< $sgs`
           sgName=`echo "${sgName//\"}"`
           sgName=`echo "$sgName" | awk '{print tolower($0)}'`
           sgId=`jq '.[] | .GroupId?' <<< $sgs`
         fi
        
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
            for j in {0..50}
            do
              volId=`jq '.['$j'].Ebs?.VolumeId?' <<< $ebsvols`
              if [ "$volId" = null ]
              then
                 break
              fi
              
              # Get volume information
              volId=`echo "${volId//\"}"`
              if [[ "$volId" != *"null"* ]]
              then
                 volInfo=`aws ec2 describe-volumes --volume-ids $volId`
                 errorno=`echo $?`
                 if [ "$errorno" -ne 0 ]
                 then
                     continue
                 fi

                 if [ "$volInfo" != null ]
                 then
                   flag=`jq '.Volumes? | .[].Encrypted?' <<< $volInfo`
                     # Even if one of the volumes is not encrypted, we will set the property to be unencrypted
                   if [ "$flag" = false ]
                   then
                    encrypted=$flag
                   fi
                 fi
              fi
           done
        fi
              
       # Get the encryption status for the volume
       ebsEnc=encrypted_ebs
       if [ "$encrypted" = false ]
       then
          ebsEnc=unencrypted
       fi

       # add facts
       echo "compute($name, $ebsEnc, $type, $ipType)." >> "$FILENAME"
       echo "placement($name, $instanceId, compute, $vpc_id, $subnetId)." >> "$FILENAME"
       echo "secgrp_association($name, $sgName, $sgId)." >> "$FILENAME"
       done

       # Get ALB information
       echo -e "Processing information on ALBs in the VPC\n"
       echo "/**" >> "$FILENAME"
       echo "**" >> "$FILENAME"
       echo "* ALB information" >> "$FILENAME"
       echo "**" >> "$FILENAME"
       echo "*/" >> "$FILENAME"
      
       albinfo=`aws elbv2 describe-load-balancers`
       albinfoarray=`jq '.LoadBalancers?' <<< $albinfo`
       for i in {0..50}
       do
         albentry=$(jq '.['$i']' <<< $albinfoarray)
         if [ "$albentry" = "null" ]
         then 
           break
         fi

         # Get the ALB name
         albname=`jq '.LoadBalancerName?' <<< $albentry`
	 #albname=`echo "${albname//\"}"`
        
         dnsname=`jq '.DNSName?' <<< $albentry`
        
         # Get subnet information
         subnets=`jq '.AvailabilityZones? | .[] | .SubnetId?' <<< $albentry`
         # Extract subnet information
         for j in {1..50}
         do
           subnetid=$(jq '.['$j'] | .SubnetId' <<< $subnets)
           if [ "$subnetid" == 'null' ]
           then
              break
           fi
           # Add fact
           echo "placement($albname, $dnsname, alb, $vpc_id, $subnetid)." >> "$FILENAME"
           
         done
         
         # Get security group information
         albsgs=`jq '.SecurityGroups?' <<< $albentry`
         
         # Get all security groups
         for j in {0..50}
         do
           sg=$(jq '.['$j']' <<< $albsgs)
           if [ "$sg" = "null" ]
           then 
             break
           fi
          echo "secgrp_association($albname, $dnsname, null, $sg)." >> "$FILENAME"
         done
       done
 

       # Get RDB detailsInformation
        echo -e "Processing information on RDS instances in VPC: $vpc_id\n"
        echo "/**" >> "$FILENAME"
        echo "**" >> "$FILENAME"
        echo "* RDS information" >> "$FILENAME"
        echo "**" >> "$FILENAME"
        echo "*/" >> "$FILENAME"

       rdbinfo=`aws rds describe-db-instances`     
       rdbinfoarray=`jq '.DBInstances?' <<< $rdbinfo`
       for i in {0..50}     
       do
           rdbentry=$(jq '.['$i']' <<< $rdbinfoarray)
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

           #VPC id
           vpcid=`jq '.DBSubnetGroup? | .VpcId?' <<< $rdbentry`

           #Get subnet IDs
           subnets=`jq '.DBSubnetGroup? | .Subnets?' <<< $rdbentry`
           for j in {0..10}
           do
             subnet=$(jq '.['$j']' <<< $subnets)
             if [ "$subnet" = "null" ]
             then 
                break
             fi
             
             # Get the subnet id
             subnetid=`jq '.SubnetIdentifier?' <<< $subnet`

             # Add the palcement fact
             echo "placement($rdbinstance, $dbresourceid, rdms, $vpcid, $subnetid)." >> "$FILENAME"
          done

          # Get the security group id
          rdb_sgs=`jq '.VpcSecurityGroups?' <<< $rdbentry`
          for j in {0..10}
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
}



# Parse input arguments
for i in "$@"
do
case $i in
    -r|--region)
    REGION="${i#*=}"
    ;;
    -a|--aws_account)
    ACCOUNT="${i#*=}"
    ;;
    -v|--vpc-id)
    VPC_ID="${i#*=}"
    ;;
    -o=*|--outputfile=*)
    OUTFILE="${i#*=}"
    shift 
    ;;
    -h|--help)
    showHelp
    exit
    ;;
    *)
            # unknown option
    ;;
esac
done
echo region=$REGION, vpc_id=$VPC_ID, outputfile=$OUTPUTFILE
openfile
if [ -z "$VPC_ID" ] 
then
        # Get VPC Information
        start=`date +%s`
        echo -e "Gathering information on VPCs\n"
        vpcs_info=`aws ec2 describe-vpcs`
        # We assume there are going to be 50 VPCs, but will exit the loop if the array does not have that many
        for i in {0..50}
        do
           vpc_id=`jq '.[] | .['$i'] | .VpcId?' <<< "$vpcs_info"`
           if [ "$vpc_id" = "null" ]
           then 
             break
           fi
           cidr=`jq '.[] | . ['$i'] | .CidrBlock?' <<< "$vpcs_info"`
           cidr=`echo "${cidr//\"}"`
           cidr=`echo "ip(${cidr//./,})"`
           echo "vpc($vpc_id, $cidr, $ACCOUNT, $REGION)." >> "$FILENAME"
        
           # Now process information about the rest of the VPC resources
           processVPC $vpc_id
        done
else

        echo -e "Gathering information on VPC: $VPC_ID\n"
        vpcs_info=`aws ec2 describe-vpcs --vpc-ids $VPC_ID`
        vpc_id=$VPC_ID

        cidr=`jq '.[] | . [0] | .CidrBlock?' <<< "$vpcs_info"`
        cidr=`echo "${cidr//\"}"`
        cidr=`echo "ip(${cidr//./,})"`
        echo "vpc($vpc_id, $cidr, $ACCOUNT, $REGION)." >> "$FILENAME"
        # Now process information about the rest of the VPC resources
        processVPC $vpc_id
fi
        
end=`date +%s`
echo -e "Processing completed. Facts are in $FILENAME\n"
let elapsed=$end-$start
echo "Elapsed time: $elapsed seconds."
exit

