data "aws_iam_policy_document" "assume_role_lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "lambda.amazonaws.com"
      ]
    }
  }
}

resource "aws_iam_role" "rua" {
  name               = "${local.lambda_name}-lambda"
  assume_role_policy = data.aws_iam_policy_document.assume_role_lambda.json
  inline_policy {
    name   = "AllowSesS3Access"
    policy = data.aws_iam_policy_document.lambda_rua.json
  }
}

data "aws_iam_policy_document" "lambda_rua" {
  statement {
    resources = [
      "arn:aws:s3:::${var.s3_bucket_name_ses}/${var.rua_ses_receipt_s3_key}*"
    ]
    actions = [
      "s3:GetObject"
    ]
  }
  statement {
    resources = [
      "arn:aws:s3:::${local.s3_bucket_name_rua_report}",
      "arn:aws:s3:::${local.s3_bucket_name_rua_report}/*"
    ]
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket"
    ]
  }
  statement {
    resources = ["*"]
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
  }
}
