package rules.VPC_TAG

input_type := "tf"

resource_type := "aws_vpc"

metadata := {
	"id": "VPC_TAG",
	"severity": "critical",
	"title": "Owner Tag must be applied to VPCs",
	"description": "All VPCs must have an Owner tag applied",
	"product": [
		"iac",
		"cloud",
	],
}

deny[info] {
	# TODO: add conditions so that this rule only returns when input is invalid. For example:
	# input.some_property == "bad value"
	not input.tags.Owner
	info := {"resource": input}
}
