variable "prefix" {
  description = "Prefix"
  type        = string
  default     = ""
}

variable "suffix" {
  description = "Suffix"
  type        = string
  default     = ""
}

variable "service_name" {
  description = "Service name"
  type        = string
}

variable "lambda_python_version" {
  description = "Python version"
  type        = string
}

variable "slack_channel" {
  description = "Slack channel name for notifications"
  type        = string
}

variable "slack_token" {
  description = "Slack token"
  type        = string
}

variable "s3_bucket_name_ses" {
  description = "S3 bucket ARN to store mail"
  type        = string
}

variable "s3_bucket_arn_ses" {
  description = "S3 bucket ARN to store mail"
  type        = string
}

variable "ses_rule_set_name" {
  description = "ses rule set name"
  type        = string
}

variable "dmarc_rua_mailto" {
  description = "dmarc rua mailto"
  type        = string
}

variable "cloudwatch_log_retention_days" {
  description = "CloudWatch Log retention period in days"
  default     = null
}

variable "image_presigned_url_access_key_id" {
  description = "image presigned url access key id"
  type        = string
  default     = null
}

variable "image_presigned_url_secret_access_key" {
  description = "image presigned url secret access key"
  type        = string
  default     = null
}

variable "rua_ses_receipt_s3_key" {
  description = "receipt rua report key"
  type        = string
  default     = "rua/"
}
