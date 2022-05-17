policy "aws_securityhub_standards_subscription" {
    enforcement_level = "hard-mandatory"
    source = "./SentinelPolicies/aws_security.sentinel"
}
