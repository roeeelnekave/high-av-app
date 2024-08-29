resource "aws_key_pair" "high-av-key" {
  key_name   = "high-av-key"
  public_key = file(var.key-name)  
}