resource "aws_lambda_function" "lambda_zip" {
  function_name    = "${local.prefix}-lambda"
  runtime          = "python3.9"
  handler          = "lib.lambda.lambda_handler"
  filename         = "zip/lambda.zip"
  role             = aws_iam_role.lambda_role.arn
  timeout          = 600
  layers           = [aws_lambda_layer_version.lambda_layer.id]
  source_code_hash = filebase64sha256("zip/lambda.zip")

}

# IAM

data "aws_iam_policy_document" "lambda_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_role" {
  name               = "lambda_role"
  assume_role_policy = data.aws_iam_policy_document.lambda_role.json
}

# Logs

data "aws_iam_policy_document" "lambda_logging" {
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "arn:aws:logs:*:*:*",
    ]
  }
}

resource "aws_iam_policy" "lambda_logging" {
  name   = "${local.prefix}-policy-logging"
  path   = "/"
  policy = data.aws_iam_policy_document.lambda_logging.json
}

resource "aws_iam_role_policy_attachment" "lambda_logging" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

# Security Hub

data "aws_iam_policy_document" "lambda_securityhub" {
  statement {
    actions = [
      "securityhub:GetFindings",
      "securityhub:ListFindingAggregators",
      "iam:ListAccountAliases"
    ]
    resources = [
      "*"
    ]
  }
}

resource "aws_iam_policy" "lambda_policy_securityhub" {
  name   = "${local.prefix}-policy-securityhub"
  path   = "/"
  policy = data.aws_iam_policy_document.lambda_securityhub.json
}

resource "aws_iam_role_policy_attachment" "lambda_attach_securityhub" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy_securityhub.arn
}

# Layer

resource "aws_lambda_layer_version" "lambda_layer" {
  filename   = "zip/metahub-layer.zip"
  layer_name = "metahub_layer"

  compatible_runtimes = ["python3.9"]
}
