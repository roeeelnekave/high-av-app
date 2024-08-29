resource "aws_iam_role" "high-av-ec2-role" {

 name = "high-av-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
      tag-key = "high-vpc"
  }
}


resource "aws_iam_instance_profile" "high-av-ec2-profile" {
  name = "high-av-policy"
  role = aws_iam_role.high-av-ec2-role.name
}

resource "aws_iam_role_policy" "hih-av-policy" {
  name = "high-av-policy"
  role = aws_iam_role.high-av-ec2-role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:*",
        "secretsmanager:*",
        "rds:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}