resource "aws_s3_object" "rua" {
  bucket = var.s3_bucket_name_ses
  acl    = "private"
  key    = var.rua_ses_receipt_s3_key
  source = "/dev/null"
}

resource "aws_s3_bucket_notification" "rua" {
  bucket      = var.s3_bucket_name_ses
  eventbridge = false
  lambda_function {
    events = [
      "s3:ObjectCreated:*"
    ]
    filter_prefix       = var.rua_ses_receipt_s3_key
    lambda_function_arn = aws_lambda_function.rua.arn

  }
}

resource "aws_s3_bucket" "report" {
  bucket = local.s3_bucket_name_rua_report
}

resource "aws_s3_bucket" "lambda_deploy" {
  bucket = "${local.qualified_service_name}-rua-analysis-lambda-deploy"
}

resource "aws_s3_bucket_lifecycle_configuration" "rua" {
  bucket = var.s3_bucket_name_ses

  rule {
    id = "rua"

    expiration {
      days = 360
    }

    filter {
      and {
        prefix = var.rua_ses_receipt_s3_key

        tags = {
          rule      = "rua"
          autoclean = "true"
        }
      }
    }

    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "report" {
  bucket = aws_s3_bucket.report.bucket

  rule {
    id = "report"

    expiration {
      days = 360
    }

    filter {
      and {
        tags = {
          rule      = "report"
          autoclean = "true"
        }
      }
    }

    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }
  }
}
