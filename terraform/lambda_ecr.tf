# 1.  Create a Private ECR
# 2. Build

# aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 317105492065.dkr.ecr.us-east-1.amazonaws.com

# docker build -f ./Dockerfile-lambda -t "317105492065.dkr.ecr.us-east-1.amazonaws.com/ecr-metahub-private:test2" .

# docker push 317105492065.dkr.ecr.us-east-1.amazonaws.com/ecr-metahub-private:test1

# 3. Deploy Lambda


resource "aws_ecr_repository" "repo" {
  name = "ecr-metahub-private"
}

resource "aws_lambda_function" "lambda_ecr" {
  function_name    = "${local.prefix}-lambda-ecr"
  image_uri         = "${aws_ecr_repository.repo.repository_url}:test2"
  package_type     = "Image"
  role             = aws_iam_role.lambda_role.arn
  timeout          = 600
  architectures    = ["arm64"]

}

# resource null_resource ecr_image {
#  triggers = {
#    docker_file = md5(file("${path.module}/../Dockerfile"))
#  }

#  provisioner "local-exec" {
#    command = <<EOF              
#            aws ecr get-login-password --region ${var.region} | docker login --username AWS --password-stdin ${local.account_id}.dkr.ecr.${var.region}.amazonaws.com
#            docker build -t ${aws_ecr_repository.repo.repository_url}:${local.ecr_image_tag} .
#            docker push ${aws_ecr_repository.repo.repository_url}:${local.ecr_image_tag}
#        EOF
#  }
# }

# resource "aws_lambda_function" "executable" {
#   function_name = "test"
#   image_uri     = "${aws_ecr_repository.image_storage.repository_url}:latest"
#   package_type  = "Image"
#   role          = aws_iam_role.lambda.arn
# }
