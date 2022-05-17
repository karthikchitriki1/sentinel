 import "tfplan/v2" as tfplan
allrule = filter tfplan.resource_changes as _, rc {
  rc.type is "aws_securityhub_standards_subscription" and
  rc.mode is "managed" and
  (rc.change.actions) contains "create" or rc.change.actions contains "update" or
   rc.change.actions contains "read" or rc.change.actions contains "no op"
}
violatedrulecount = 0
for allrule as groupdetails, sh {
  if sh["CIS AWS FOUNDATIONS"]["standards_arn"] is not "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0" {
      violatedrulecount=violatedrulecount+1
      print("security hub is not implemented")
    }
    if sh["CIS AWS FOUNDATIONS"]["standards_arn"] is "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0" {
      print("security hub is implemented")
    }
}
main=rule {
  violatedrulecount=violatedrulecount<=0
}

