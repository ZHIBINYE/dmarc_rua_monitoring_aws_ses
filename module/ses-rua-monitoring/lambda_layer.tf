module "lambda_layer" {
  source  = "kota65535/python-lambda-layer/aws"
  version = "0.2.0"

  name              = local.lambda_name
  python_version    = local.python_version
  requirements_path = "${path.module}/lambda/requirements.txt"
  output_path       = "${data.temporary_directory.lambda.id}/${local.lambda_name}-layer.zip"
}
