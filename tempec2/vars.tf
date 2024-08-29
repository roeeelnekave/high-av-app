variable "ami-id" {
  type = string
  description = "AMI ID"
  default = "ami-05134c8ef96964280"
}

variable "public_key_path" {
  type = string
  description = "The public key path"
  default = "id_rsa.pub"
}

