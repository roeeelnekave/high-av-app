provider "aws" {
  region = "us-west-2"
}

data "terraform_remote_state" "network" {
  backend = "local"
  config = {
    path = "../terraform/terraform.tfstate"
  }
}
resource "aws_security_group" "instance_sg" {
  name        = "instance_sg"
  description = "Allow ports 22, 80"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami           = var.ami-id  
  instance_type = "t2.micro"
  key_name      = aws_key_pair.deployer.key_name
  vpc_security_group_ids = [aws_security_group.instance_sg.id]

  tags = {
    Name = "amimaker"
  }

  provisioner "local-exec" {
    command = "echo '${self.public_ip}' >> inventory "
  }
}