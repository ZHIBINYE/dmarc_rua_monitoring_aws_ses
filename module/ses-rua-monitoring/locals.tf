locals {
  qualified_service_name    = join("-", compact([var.prefix, var.service_name, var.suffix]))
  lambda_name               = join("-", [local.qualified_service_name, "ses-rua-monitoring"])
  python_version            = regex("^(\\d+\\.\\d+)(\\.\\d+)?$", var.lambda_python_version)[0]
  lambda_runtime            = "python${local.python_version}"
  s3_bucket_name_rua_report = join("-", compact([local.qualified_service_name, "ses-rua-report", data.aws_caller_identity.self.account_id]))
}

data "aws_caller_identity" "self" {}

data "aws_region" "self" {}
