resource "aws_vpc" "high-av" {
  cidr_block       = var.vpc-cidr
  instance_tenancy = "default"

  tags = {
    Name = "high-av"
  }
}
