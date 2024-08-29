resource "aws_lambda_function" "rua" {
  function_name    = local.lambda_name
  handler          = "function.lambda_handler"
  description      = "SES send s3 mail event"
  role             = aws_iam_role.rua.arn
  runtime          = local.lambda_runtime
  timeout          = 60
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  layers = ["arn:aws:lambda:ap-northeast-1:770693421928:layer:Klayers-p311-requests:10",
    "arn:aws:lambda:ap-northeast-1:770693421928:layer:Klayers-p311-matplotlib:9",
    module.lambda_layer.lambda_layer_version.arn
  ]
  filename = data.archive_file.lambda_zip.output_path

  environment {
    variables = {
      SLACK_BOT_TOKEN                       = var.slack_token
      IMAGE_PRESIGNED_URL_ACCESS_KEY_ID     = var.image_presigned_url_access_key_id
      IMAGE_PRESIGNED_URL_SECRET_ACCESS_KEY = var.image_presigned_url_secret_access_key
      SAVE_REPORT_S3_BUCKET                 = aws_s3_bucket.report.bucket
      SLACK_CHANNEL                         = var.slack_channel
    }
  }
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${data.temporary_directory.lambda.id}/${local.lambda_name}.zip"

  source {
    content  = file("${path.module}/lambda/src/function.py")
    filename = "function.py"
  }
  source {
    content  = file("${path.module}/lambda/src/config.py")
    filename = "config.py"
  }
  source {
    content  = file("${path.module}/lambda/src/handler.py")
    filename = "handler.py"
  }
  source {
    content  = file("${path.module}/lambda/src/utils.py")
    filename = "utils.py"
  }
}

data "temporary_directory" "lambda" {
  name = "lambda/${local.lambda_name}"
}

resource "aws_lambda_permission" "rua_allow_bucket" {
  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rua.arn
  principal     = "s3.amazonaws.com"
  source_arn    = var.s3_bucket_arn_ses
}
