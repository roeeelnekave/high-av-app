variable "vpc-cidr" {
  type = string
  description = "VPC CIDR block"
  default = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
 type        = list(string)
 description = "Public Subnet CIDR values"
 default     = ["10.0.1.0/24", "10.0.2.0/24"]
}
 
variable "private_subnet_cidrs" {
 type        = list(string)
 description = "Private Subnet CIDR values"
 default     = ["10.0.3.0/24", "10.0.4.0/24"]
}

variable "ami-id" {
  type = string
  description = "AMI ID"
  default = "ami-05134c8ef96964280"
}

variable "instance-type" {
  type = string
  description = "Instance type"
  default = "t2.micro"
}

variable "key-name" {
  type = string
  description = "Key file path"
  default = "mykey.pub"
}

variable "user-name" {
 type = string
 description = "user name for RDS"
 default = "roeeelnekave"
}

variable "password" {
 type = string
 description = "password RDS"
 default = "roeeel*nekaveE1234"
}

variable "rds_subnet_cidrs" {
  default = ["10.0.5.0/24", "10.0.6.0/24"]
}