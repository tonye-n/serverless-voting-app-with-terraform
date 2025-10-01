provider "aws" {
  region  = "us-west-2"
  profile = "AdministratorAccess-471112797289"
}

# --------------------------------------------------------- 
# Module 2 - Backend APIs
# ---------------------------------------------------------

resource "aws_dynamodb_table" "votes_table" {
  name         = "${var.app_name}-vote-result"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "PK"
  range_key    = "SK"

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  # enable dynamodb streaming
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  tags = {
    Terraform   = "true"
    Environment = "dev"
    Application = var.app_name
  }
}

module "get-votes" {
  source = "terraform-aws-modules/lambda/aws"

  function_name   = "${var.app_name}-get-votes"
  description     = "get votes"
  handler         = "index.handler"
  runtime         = "nodejs18.x"
  memory_size     = 256
  build_in_docker = true

  source_path = "src/get-votes"

  environment_variables = {
    DDB_TABLE_NAME = aws_dynamodb_table.votes_table.id
  }

  attach_policy_statements = true
  policy_statements = {
    dynamodb = {
      effect = "Allow",
      actions = [
        "dynamodb:Scan",
      ],
      resources = [aws_dynamodb_table.votes_table.arn]
    }
  }

  create_current_version_allowed_triggers = false
  allowed_triggers = {
    APIGatewayAny = {
      service    = "apigateway"
      source_arn = "${module.api_gateway.api_execution_arn}/*/*"
    }
  }

  tags = {
    Terraform   = "true"
    Environment = "dev"
    Application = var.app_name
  }
}

module "post-votes" {
  source = "terraform-aws-modules/lambda/aws"

  function_name   = "${var.app_name}-post-votes"
  description     = "post votes"
  handler         = "index.handler"
  runtime         = "nodejs18.x"
  memory_size     = 256
  build_in_docker = true

  source_path = "src/post-votes"

  environment_variables = {
    DDB_TABLE_NAME = aws_dynamodb_table.votes_table.id
  }

  attach_policy_statements = true
  policy_statements = {
    dynamodb = {
      effect = "Allow",
      actions = [
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:ConditionCheckItem",
      ],
      resources = [aws_dynamodb_table.votes_table.arn]
    }
  }

  create_current_version_allowed_triggers = false
  allowed_triggers = {
    APIGatewayAny = {
      service    = "apigateway"
      source_arn = "${module.api_gateway.api_execution_arn}/*/*"
    }
  }

  tags = {
    Terraform   = "true"
    Environment = "dev"
    Application = var.app_name
  }
}

module "api_gateway" {
  source = "terraform-aws-modules/apigateway-v2/aws"

  name          = "${var.app_name}-api"
  description   = "voting api"
  protocol_type = "HTTP"

  cors_configuration = {
    allow_headers = ["content-type", "x-amz-date", "authorization", "x-api-key", "x-amz-security-token", "x-amz-user-agent"]
    allow_methods = ["*"]
    allow_origins = ["*"]
  }

  create_domain_name = false
  create_stage       = true
  stage_name         = "$default"

  # Routes and integrations.
  routes = {
    "GET /votes" = {
      integration = {
        uri    = module.get-votes.lambda_function_arn
        type   = "AWS_PROXY"
        method = "POST"

        payload_format_version = "2.0"
      }
    }
    "POST /votes" = {
      integration = {
        description     = "integrate with Vote SQS queue"
        type            = "AWS_PROXY"
        subtype         = "SQS-SendMessage"
        credentials_arn = aws_iam_role.apigw_sqs_role.arn

        request_parameters = {
          "QueueUrl"    = module.votes_queue.queue_id
          "MessageBody" = "$request.body"
        }
      }
    }
  }

  tags = {
    Terraform   = "true"
    Environment = "dev"
    Application = var.app_name
  }

}


# --------------------------------------------------------- 
# Module 3 - Aync Writes
# ---------------------------------------------------------

resource "aws_iam_role" "apigw_sqs_role" {
  name = "${var.app_name}-apigw_sqs_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "apigateway.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    Terraform   = "true"
    Environment = "dev"
    Application = var.app_name
  }
}

resource "aws_iam_role_policy" "sqs_integration" {
  name = "sqs_integration_policy"
  role = aws_iam_role.apigw_sqs_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "sqs:SendMessage",
          "sqs:SendMessageBatch"
        ]
        Effect   = "Allow"
        Resource = module.votes_queue.queue_arn
      },
    ]
  })
}

module "votes_queue" {
  source = "terraform-aws-modules/sqs/aws"

  name = "${var.app_name}-votes-queue"

  tags = {
    Service     = "user"
    Environment = "dev"
  }
}

module "count-votes" {
  source = "terraform-aws-modules/lambda/aws"

  function_name   = "${var.app_name}-count-votes"
  description     = "batch couting function"
  handler         = "index.handler"
  runtime         = "nodejs18.x"
  memory_size     = 256
  build_in_docker = true

  source_path = "src/count-votes"

  environment_variables = {
    QUEUE_URL      = module.votes_queue.queue_id
    DDB_TABLE_NAME = aws_dynamodb_table.votes_table.id
  }

  event_source_mapping = {
    sqs = {
      event_source_arn                   = module.votes_queue.queue_arn
      batch_size                         = 1000
      maximum_batching_window_in_seconds = 1
    }
  }

  allowed_triggers = {
    sqs = {
      principal  = "sqs.amazonaws.com"
      source_arn = module.votes_queue.queue_arn
    }
  }

  create_current_version_allowed_triggers = false

  tracing_mode          = "Active"
  attach_tracing_policy = true

  attach_policies    = true
  number_of_policies = 1

  policies = [
    "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole",
  ]

  attach_policy_statements = true
  policy_statements = {
    dynamodb = {
      effect = "Allow",
      actions = [
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:ConditionCheckItem"
      ],
      resources = [aws_dynamodb_table.votes_table.arn]
    }
  }

  tags = {
    Terraform   = "true"
    Environment = "dev"
    Application = var.app_name
  }
}


# ---------------------------------------------------------
# Module 4 - Realtime Updates
# ---------------------------------------------------------

# ---------------------------------------------------------
# Module 4 - Realtime Updates
# ---------------------------------------------------------

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_iot_endpoint" "current" {
  endpoint_type = "iot:Data-ATS"
}

module "realtime-update" {
  source = "terraform-aws-modules/lambda/aws"

  function_name   = "${var.app_name}-realtime-update"
  description     = "realtime update function"
  handler         = "index.handler"
  runtime         = "nodejs18.x"
  memory_size     = 256
  build_in_docker = true

  source_path = "src/realtime-update"

  environment_variables = {
    IOT_ENDPOINT = data.aws_iot_endpoint.current.endpoint_address
  }

  event_source_mapping = {
    dynamodb = {
      event_source_arn  = aws_dynamodb_table.votes_table.stream_arn
      starting_position = "LATEST"
    }
  }

  allowed_triggers = {
    dynamodb = {
      principal  = "dynamodb.amazonaws.com"
      source_arn = aws_dynamodb_table.votes_table.stream_arn
    }
  }

  create_current_version_allowed_triggers = false

  tracing_mode          = "Active"
  attach_tracing_policy = true

  attach_policies    = true
  number_of_policies = 1

  policies = [
    "arn:aws:iam::aws:policy/service-role/AWSLambdaDynamoDBExecutionRole",
  ]

  attach_policy_statements = true
  policy_statements = {
    iotcore = {
      effect = "Allow",
      actions = [
        "iot:Publish",
      ],
      resources = ["arn:aws:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:topic/votes"]
    }
  }

  tags = {
    Terraform   = "true"
    Environment = "dev"
    Application = var.app_name
  }

}

resource "aws_cognito_identity_pool" "main" {
  identity_pool_name               = "${var.app_name}-identity_pool"
  allow_unauthenticated_identities = true

  tags = {
    Terraform   = "true"
    Environment = "dev"
    Application = var.app_name
  }
}

resource "aws_iam_role" "unauthenticated" {
  name = "${var.app_name}-cognito_poolUnauth_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "cognito-identity.amazonaws.com"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "cognito-identity.amazonaws.com:aud" : "${aws_cognito_identity_pool.main.id}"
          },
          "ForAnyValue:StringLike" : {
            "cognito-identity.amazonaws.com:amr" : "unauthenticated"
          }
        }
      }
    ]
  })

  tags = {
    Terraform   = "true"
    Environment = "dev"
    Application = var.app_name
  }
}

resource "aws_iam_role_policy" "unauthenticated_policy" {
  name = "cognito_iot_unauthenticated_policy"
  role = aws_iam_role.unauthenticated.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["iot:Connect"]
        Effect   = "Allow"
        Resource = ["arn:aws:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:client/*"]
      },
      {
        Action   = ["iot:Receive"]
        Effect   = "Allow"
        Resource = ["arn:aws:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:topic/votes"]
      },
      {
        Action   = ["iot:Subscribe"]
        Effect   = "Allow"
        Resource = ["arn:aws:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:topicfilter/votes"]
      },
    ]
  })
}

resource "aws_iam_role" "authenticated" {
  name = "${var.app_name}-cognito_poolAuth_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "cognito-identity.amazonaws.com"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "cognito-identity.amazonaws.com:aud" : "${aws_cognito_identity_pool.main.id}"
          },
          "ForAnyValue:StringLike" : {
            "cognito-identity.amazonaws.com:amr" : "authenticated"
          }
        }
      }
    ]
  })

  tags = {
    Terraform   = "true"
    Environment = "dev"
    Application = var.app_name
  }
}

resource "aws_cognito_identity_pool_roles_attachment" "main" {
  identity_pool_id = aws_cognito_identity_pool.main.id

  roles = {
    "unauthenticated" = aws_iam_role.unauthenticated.arn
    "authenticated"   = aws_iam_role.authenticated.arn
  }
}