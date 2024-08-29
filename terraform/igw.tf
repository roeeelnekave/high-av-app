resource "aws_internet_gateway" "gw" {
 vpc_id = aws_vpc.high-av.id
 
 tags = {
   Name = "Project VPC IG"
 }
}