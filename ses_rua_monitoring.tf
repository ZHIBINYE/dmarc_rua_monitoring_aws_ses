module "ses-rua-monitoring" {
  source = "./module/ses-rua-monitoring"

  # Name
  prefix       = "example"
  service_name = "dmarc-monitoring"

  # pythonバージョンは3.11で固定
  lambda_python_version = "3.11"

  # S3 email
  s3_bucket_name_ses     = "ses-emails-XXXXXXXXXXX"
  s3_bucket_arn_ses      = "arn:aws:s3:::ses-emails-XXXXXXXXXXX"
  rua_ses_receipt_s3_key = "serverless/"
  # rule set name
  ses_rule_set_name = "rule-set"
  # rua mailto mail address
  dmarc_rua_mailto = "dmarc-sample@example.co.jp"

  # CloudWatch
  cloudwatch_log_retention_days = 180

  # s3 image ge url iam user
  # presigned url will be expired in max 12 hours if use lambda role.
  # set user access info please, if you want to set date of expiry in max 7 days.
  image_presigned_url_access_key_id     = null
  image_presigned_url_secret_access_key = null
  # Slack
  slack_channel = "ye-dev-notice"
  slack_token   = "slack api token"
}
