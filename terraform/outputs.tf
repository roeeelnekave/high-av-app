# outputs.tf
output "vpc_id" {
  value = aws_vpc.high-av.id
}

output "public_subnet_ids" {
  value = aws_subnet.public_subnets[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private_subnets[*].id
}

# output "efs_security_group_id" {
#   value = aws_security_group.efs_sg.id
# }

# output "app_security_group_id" {
#   value = aws_security_group.app_sg.id
# }
