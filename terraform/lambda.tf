# Create an archive file with your Lambda function code

# data "archive_file" "lambda_code" {
#   type        = "zip"
#   source_dir  = "../${path.module}/lib"  # Path to your Lambda function code
#   output_path = "${path.module}/zip/lambda_code.zip"
# }

resource "null_resource" "create_lambda" {
  # This resource serves as a trigger for the local-exec provisioners
  triggers = {
    always_run = "${timestamp()}"
  }

  provisioner "local-exec" {
    command = "cd .. && zip -qr terraform/zip/lambda_code.zip lib && cd terraform"
  }

  provisioner "local-exec" {
    # Use openssl to calculate SHA-256 hash
    command = "cd zip && openssl dgst -sha256 -binary lambda_code.zip | openssl base64 -A > lambda_code_sha256.txt && cd .."
  }
}

data "local_file" "code_hash" {
  depends_on = [null_resource.create_lambda]
  filename   = "zip/lambda_code_sha256.txt"
}

resource "aws_lambda_function" "lambda_zip" {
  depends_on = [null_resource.create_lambda]

  function_name    = "${local.prefix}-lambda"
  runtime          = "python3.13"
  handler          = "lib.lambda.lambda_handler"
  filename         = "zip/lambda_code.zip"
  role             = aws_iam_role.lambda_role.arn
  timeout          = 600
  layers           = [aws_lambda_layer_version.lambda_layer.id]
  source_code_hash = data.local_file.code_hash.content
  memory_size      = 256

  tags = {
    Service = local.prefix
  }

}

# Lambda Layer

resource "null_resource" "create_layer" {
  # This resource serves as a trigger for the local-exec provisioners
  triggers = {
    always_run = "${timestamp()}"
  }

  provisioner "local-exec" {
    command = "mkdir -p zip/layer/python/lib/python3.9/site-packages"
  }

  provisioner "local-exec" {
    command = "pip3 install -r ../requirements.txt --target zip/layer/python/lib/python3.9/site-packages"
  }

  provisioner "local-exec" {
    command = "cd zip/layer && zip -rq9 ../metahub_layer.zip . && cd .."
  }

  provisioner "local-exec" {
    # Use openssl to calculate SHA-256 hash
    command = "cd zip && openssl dgst -sha256 -binary metahub_layer.zip | openssl base64 -A > metahub_layer_sha256.txt && cd .."
  }

  provisioner "local-exec" {
    command = "rm -r zip/layer"
  }
}

data "local_file" "layer_hash" {
  depends_on = [null_resource.create_layer]
  filename   = "zip/metahub_layer_sha256.txt"
}

resource "aws_lambda_layer_version" "lambda_layer" {
  depends_on = [null_resource.create_layer]

  filename            = "zip/metahub_layer.zip"
  layer_name          = "metahub_layer"
  source_code_hash    = data.local_file.layer_hash.content
  compatible_runtimes = ["python3.9"]
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

  tags = {
    Service = local.prefix
  }
}

# IAM Lambda Logs

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

  tags = {
    Service = local.prefix
  }
}

resource "aws_iam_role_policy_attachment" "lambda_logging" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

# IAM Security Hub

data "aws_iam_policy_document" "lambda_securityhub" {
  statement {
    actions = [
      "securityhub:GetFindings",
      "securityhub:ListFindingAggregators",
      "iam:ListAccountAliases",
      "securityhub:BatchUpdateFindings"
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

  tags = {
    Service = local.prefix
  }
}

resource "aws_iam_role_policy_attachment" "lambda_attach_securityhub" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy_securityhub.arn
}

# IAM Context

data "aws_iam_policy_document" "lambda_policy_document_metachecks" {
  statement {
    actions = [
      "lambda:GetFunction",
      "lambda:GetFunctionUrlConfig",
    ]
    resources = [
      "*"
    ]
  }
}

resource "aws_iam_policy" "lambda_policy_metachecks" {
  name   = "${local.prefix}-policy-metachecks"
  path   = "/"
  policy = data.aws_iam_policy_document.lambda_policy_document_metachecks.json

  tags = {
    Service = local.prefix
  }
}

resource "aws_iam_role_policy_attachment" "lambda_attach_metaachecks" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy_metachecks.arn
}

resource "aws_iam_role_policy_attachment" "lambda_attach_securityaudit" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# IAM MetaAccount

data "aws_iam_policy_document" "lambda_policy_document_metaaccount" {
  statement {
    actions = [
      "account:GetAlternateContact"
    ]
    resources = [
      "*"
    ]
  }
}

resource "aws_iam_policy" "lambda_policy_metaaccount" {
  name   = "${local.prefix}-policy-metaaccount"
  path   = "/"
  policy = data.aws_iam_policy_document.lambda_policy_document_metaaccount.json

  tags = {
    Service = local.prefix
  }
}

resource "aws_iam_role_policy_attachment" "lambda_attach_metaaccount" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy_metaaccount.arn
}
