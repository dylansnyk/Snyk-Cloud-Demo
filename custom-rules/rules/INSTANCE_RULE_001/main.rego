package rules.INSTANCE_RULE_001

input_type := "tf"

resource_type := "aws_instance"

metadata := {
	"id": "INSTANCE_RULE_001",
	"severity": "critical",
	"title": "No public ec2 instances",
	"description": "We are not allowing public ips to be associated with our instances",
	"product": [
		"iac",
		"cloud",
	],
}

deny[info] {
	input.associate_public_ip_address == true
	# TODO: add conditions so that this rule only returns when input is invalid. For example:
	# input.some_property == "bad value"
	info := {"resource": input}
}
