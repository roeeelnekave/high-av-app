resource "aws_eip" "nat" {
  count = length(var.public_subnet_cidrs)
  domain = "vpc"
}

resource "aws_nat_gateway" "natgw" {
  count = length(var.public_subnet_cidrs)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public_subnets[count.index].id  # Attach each NAT Gateway to the corresponding public subnet

  tags = {
    Name = "NAT Gateway ${count.index + 1}"
  }
}

resource "aws_route_table" "private_route_table" {
  count = length(var.private_subnet_cidrs)
  vpc_id = aws_vpc.high-av.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.natgw[count.index].id  # Associate each route table with the corresponding NAT Gateway
  }

  tags = {
    Name = "Private Route Table ${count.index + 1}"
  }
}

resource "aws_route_table_association" "private_subnet_association" {
  count = length(var.private_subnet_cidrs)
  subnet_id      = aws_subnet.private_subnets[count.index].id  # Associate each private subnet with its corresponding route table
  route_table_id = aws_route_table.private_route_table[count.index].id
}
