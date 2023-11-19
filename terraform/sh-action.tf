resource "aws_securityhub_action_target" "action" {
  name        = "MetaHub"
  identifier  = "MetaHub"
  description = "Executes MetaHub"
}

resource "aws_cloudwatch_event_rule" "rule" {
  name        = "metahub-rule"
  description = "Capture each AWS Console Sign In"

  event_pattern = jsonencode({
    "source" : ["aws.securityhub"],
    "detail-type" : ["Security Hub Findings - Custom Action"],
    "resources" : ["${aws_securityhub_action_target.action.arn}"],
  })
}

resource "aws_cloudwatch_event_target" "target" {
  rule      = aws_cloudwatch_event_rule.rule.name
  target_id = "SendToMetaHub"
  arn       = aws_lambda_function.lambda_zip.arn
}

resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_zip.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.rule.arn
}
