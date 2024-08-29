resource "aws_ses_receipt_rule" "rua" {
  rule_set_name = var.ses_rule_set_name
  name          = "${local.qualified_service_name}-rua"
  recipients    = [var.dmarc_rua_mailto]
  enabled       = true
  scan_enabled  = true

  s3_action {
    bucket_name       = var.s3_bucket_name_ses
    object_key_prefix = var.rua_ses_receipt_s3_key
    position          = 1
  }
}
