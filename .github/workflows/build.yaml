# Prerequisites 

- Ansible
- Terrafrom
- Github 
- Github actions

### Create a github repository and clone it and Setup a folder structure

```bash
mkdir -p ./.github/workflows
mkdir -p ./terraform
mkdir -p ./ansible
mkdir -p ./templates
mkdir -p ./tempec2
```

### Setup infrastructure
- Create a provider file `touch ./terraform/providers.tf` and paste the following
```
provider "aws" {
  region = "us-west-2"
}
```
1. To setup a infrastructure we create a vpc to do so we create `touch ./terraform/vpc.tf` and paste the following in `./terraform/vpc.tf`
```
resource "aws_vpc" "high-av" {
  cidr_block       = var.vpc-cidr
  instance_tenancy = "default"

  tags = {
    Name = "high-av"
  }
}
```
2. We then create subnet to create subnet create a file `touch ./terraform/subnets.tf` and paste the following in `./terraform/subnets.tf`
```
resource "aws_subnet" "public_subnets" {
  count             = length(var.public_subnet_cidrs)
  vpc_id            = aws_vpc.high-av.id
  cidr_block        = element(var.public_subnet_cidrs, count.index)
  availability_zone = element(data.aws_availability_zones.available.names, count.index)

  tags = {
    Name = "Public Subnet ${count.index + 1}"
  }
}

resource "aws_subnet" "private_subnets" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.high-av.id
  cidr_block        = element(var.private_subnet_cidrs, count.index)
  availability_zone = element(data.aws_availability_zones.available.names, count.index)

  tags = {
    Name = "Private Subnet ${count.index + 1}"
  }
}

resource "aws_subnet" "rds_subnets" {
  count             = length(var.rds_subnet_cidrs)
  vpc_id            = aws_vpc.high-av.id
  cidr_block        = element(var.rds_subnet_cidrs, count.index)
  availability_zone = element(data.aws_availability_zones.available.names, count.index)

  tags = {
    Name = "RDS Subnet ${count.index + 1}"
  }
}

resource "aws_db_subnet_group" "rds_subnet_group" {
  name       = "rds-subnet-group"
  subnet_ids = aws_subnet.rds_subnets[*].id

  tags = {
    Name = "RDS Subnet Group"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

```
3. Then we create natgateway to do so create a file `touch ./terraform/natgateway.tf` and paste the following in it:
```
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

```
4. Then we create a route tables to create that `touch ./terraform/routetable.tf`

```
resource "aws_route_table" "second_rt" {
 vpc_id = aws_vpc.high-av.id
 
 route {
   cidr_block = "0.0.0.0/0"
   gateway_id = aws_internet_gateway.gw.id
 }
 
 tags = {
   Name = "2nd Route Table"
 }
}

resource "aws_route_table_association" "public_subnet_asso" {
 count = length(var.public_subnet_cidrs)
 subnet_id      = element(aws_subnet.public_subnets[*].id, count.index)
 route_table_id = aws_route_table.second_rt.id
}

```
5. We create also create a internet gateway to do create a file `touch ./terraform/igw.tf` and paste the following to it
```
resource "aws_internet_gateway" "gw" {
 vpc_id = aws_vpc.high-av.id
 
 tags = {
   Name = "Project VPC IG"
 }
}
```

6. We create a security groups `touch ./terraform/securitygroup.tf`

```
resource "aws_security_group" "app_sg" {
  vpc_id = aws_vpc.high-av.id

  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Opens port 5000 to anywhere
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "App Security Group"
  }
}

resource "aws_security_group" "elb_sg" {
  name        = "high-av-elb-sg"
  description = "Security group for high availability ELB"
  vpc_id      = aws_vpc.high-av.id

  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Open to all for port 5000
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Allow all outbound traffic
  }

  tags = {
    Name = "high-av-elb-sg"
  }
}

resource "aws_security_group" "db_sg" {
  name = "my-db-sg"
  vpc_id = aws_vpc.high-av.id
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Adjust for your security needs
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Allow all outbound traffic
  }
}

resource "aws_security_group" "efs_sg" {
  name        = "efs-sg"
  description = "Security group for EFS"
  vpc_id      = aws_vpc.high-av.id

  ingress {
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Adjust this as necessary
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "EFS SG"
  }
}

```

7. We create a iam role for ec2 to fetch secrets manager and database secrets  to do that create a file `touch ./terraform/iam.tf` and paste the following

```
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
```
8. Now we create our launch template to do that `touch ./terraform/launchtemplate.tf`
```
resource "aws_launch_template" "high-av" {
  name          = "high-av"
  image_id      = var.ami-id
  instance_type = var.instance-type
  key_name      = aws_key_pair.high-av-key.key_name
  iam_instance_profile {
    name = aws_iam_instance_profile.high-av-ec2-profile.name
  } 
  

  monitoring {
    enabled = true
  }

  vpc_security_group_ids = [aws_security_group.app_sg.id]
  # Leave out the network interface configuration; this will be handled by the autoscaling group
  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "high-av"
    }
  }
}

```

9. Then we create a autoscalling group to do that create a file `touch ./terraform/autoscalling.tf`
```
resource "aws_autoscaling_group" "high-av-asg" {
  launch_template {
    id      = aws_launch_template.high-av.id
    version = "$Latest"
  }

  vpc_zone_identifier = aws_subnet.private_subnets[*].id

  min_size           = 1
  max_size           = 3
  desired_capacity   = 2

  health_check_type         = "ELB"
  health_check_grace_period = 300

  target_group_arns = [aws_lb_target_group.high-av-tg.arn]

  tag {
    key                 = "Name"
    value               = "high-av-instance"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

```

10. We then create elastic loadbalancer and to do it we create `touch ./terraform/elb.tf` and paste the following in it
```
resource "aws_lb" "high-av-elb" {
  name               = "high-av-elb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.elb_sg.id]
  subnets            = [
    aws_subnet.public_subnets[0].id,  # AZ1
    aws_subnet.public_subnets[1].id   # AZ2
  ]

  enable_deletion_protection = false

  tags = {
    Name = "high-av-elb"
  }
}

resource "aws_lb_listener" "alb-listener" {
  load_balancer_arn = aws_lb.high-av-elb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.high-av-tg.arn
  }
}


```

11. We then create a elb target group to do create `touch ./terraform/elb_target_group.tf` and paste the following in it
```
resource "aws_lb_target_group" "high-av-tg" {
  name     = "high-av-tg"
  port     = 5000
  protocol = "HTTP"
  vpc_id   = aws_vpc.high-av.id

  health_check {
    path                = "/"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 5
    unhealthy_threshold = 2
    matcher             = "200"
  }

  target_type = "instance"

  tags = {
    Name = "high-av-tg"
  }
}

```

12. Now we create the efs `touch ./terraform/efs.tf` and paste the following in it
```
# Create EFS
resource "aws_efs_file_system" "efs" {
  creation_token = "efs-for-high-av"
  tags = {
    Name = "high-av-efs"
  }
}

# Create EFS Mount Targets
resource "aws_efs_mount_target" "efs_mount_target" {
  count          = length(var.private_subnet_cidrs)
  file_system_id = aws_efs_file_system.efs.id
  subnet_id      = element(aws_subnet.private_subnets[*].id, count.index)
  security_groups = [aws_security_group.efs_sg.id]

  depends_on = [aws_vpc.high-av]
}

``` 
13. For key let's generate the key pair 
```bash
ssh-keygen -t rsa -b 4096 -f id_rsa -N ""
```
- then We create key `touch ./terraform/key.tf` and paste the following
```
resource "aws_key_pair" "high-av-key" {
  key_name   = "high-av-key"
  public_key = file(var.key-name)  
}
```
14. For the rds we create `touch ./terraform/rds.tf` and paste the following 
```
resource "aws_db_instance" "default" {
  allocated_storage      = 20
  storage_type           = "gp2"
  engine                 = "postgres"
  engine_version         = "16.4"
  instance_class         = "db.t3.medium"
  identifier             = "mydb"
  username               = jsondecode(data.aws_secretsmanager_secret_version.rds_secret.secret_string)["username"]
  password               = jsondecode(data.aws_secretsmanager_secret_version.rds_secret.secret_string)["password"]
  db_subnet_group_name   = aws_db_subnet_group.rds_subnet_group.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  multi_az               = true
  backup_retention_period = 7
  backup_window           = "07:00-09:00"
  skip_final_snapshot    = true
}
```
15. Then create the secret in secret manager to do `touch ./terraform/secretmanager.tf` and paste the following:
```
resource "aws_secretsmanager_secret" "rds_secret" {
  name = "rds-db-sec-023"
}

resource "aws_secretsmanager_secret_version" "rds_secret_version" {
  secret_id = aws_secretsmanager_secret.rds_secret.id

  secret_string = jsonencode({
    username = var.user-name
    password = var.password
  })
}

data "aws_secretsmanager_secret_version" "rds_secret" {
  secret_id = aws_secretsmanager_secret.rds_secret.id
  depends_on = [aws_secretsmanager_secret_version.rds_secret_version]
}
```
16. Now we create variable file `touch ./terraform/vars.tf` and paste the following replace the `password` and `username` default value as you required 
```
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
  default = "id_rsa.pub"
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
```
17. Now we create the logs for cloudwatch `touch ./terraform/logs.tf` and paste the following in it
```
resource "aws_cloudwatch_metric_alarm" "cpu_utilization_alarm" {
  alarm_name          = "high-cpu-utilization"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alarm when instance CPU utilization exceeds 80% for 2 consecutive 5-minute periods"
  # alarm_actions       = ["arn:aws:sns:us-east-1:748575089860:my-sns-topic"]  # Replace with your actual SNS topic ARN
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu_utilization_alarm" {
  alarm_name          = "high-rds-cpu-utilization"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alarm when RDS instance CPU utilization exceeds 80% for 2 consecutive 5-minute periods"
  # alarm_actions       = ["arn:aws:sns:us-east-1:748575089860:my-sns-topic"]  # Replace with your actual SNS topic ARN
}

resource "aws_cloudwatch_metric_alarm" "rds_storage_alarm" {
  alarm_name          = "high-rds-storage-utilization"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 20
  alarm_description   = "Alarm when RDS instance free storage space falls below 20% for 2 consecutive 5-minute periods"
  # alarm_actions       = ["arn:aws:sns:us-east-1:748575089860:my-sns-topic"]  # Replace with your actual SNS topic ARN
}
```
18. Create output `touch ./terraform/outputs.tf`
```
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

output "efs_security_group_id" {
  value = aws_security_group.efs_sg.id
}

output "app_security_group_id" {
  value = aws_security_group.app_sg.id
}

```
# Create a automated ami maker

1. Create a EC2 for that create `touch ./tempec2/main.tf` paste the following in it
```
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
  name        = "instance_sg1"
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
```

2. Create key file `touch ./tempec2/key.tf` and paste the following in it
```
resource "aws_key_pair" "deployer" {
  key_name   = "deployer_key"
  public_key = file(var.public_key_path)  # Point to your public key
}
```

3. Create variable file `touch ./tempec2/vars.tf` and paste the following in it 

```
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
```

4. Create a output file for grabbing public ip of the instance `touch ./tempec2/output.tf` and paste the following in it
```
output "instance_public_ip" {
  description = "Public IP of the EC2 instance"
  value       = aws_instance.web.public_ip
}
```

5. Create a `ansible.cfg` for disabling host checking  `touch ./tempec2/ansible.cfg` and paste following in it

```bash
[defaults]
host_key_checking = False
```

6. Create a ansible-playbook for configuring application `touch ./ansible/install-app.yml` and paste following in it

```yaml
- name: Install cpu API on server
  hosts: cpu-api
  remote_user: ubuntu
  become: true

  vars:
    app_dir: /home/ubuntu/high-availablity
    venv_dir: /home/ubuntu/flaskenv
    gunicorn_config: /gunicorn.py
    service_name: myflaskapp
    user: ubuntu
    group: ubuntu

  tasks:
    - name: Update package lists (on Debian/Ubuntu)
      apt:
        update_cache: yes

    - name: Install Python3, pip, and venv
      apt:
        name:
          - python3
          - python3-pip
          - python3-venv
        state: latest
        update_cache: yes

    - name: Manually create the initial virtualenv
      command:
        cmd: python3 -m venv "{{ venv_dir }}"
        creates: "{{ venv_dir }}"

    - name: Clone a GitHub repository
      git:
        repo: https://github.com/roeeelnekave/high-availablity.git
        dest: "{{ app_dir }}"
        clone: yes
        update: yes

    - name: Install requirements inside the virtual environment
      command: "{{ venv_dir }}/bin/pip install -r {{ app_dir }}/requirements.txt"
      become: true

    - name: Ensure application directory exists
      file:
        path: "{{ app_dir }}"
        state: directory
        owner: "{{ user }}"
        group: "{{ group }}"

    - name: Ensure virtual environment directory exists
      file:
        path: "{{ venv_dir }}"
        state: directory
        owner: "{{ user }}"
        group: "{{ group }}"

    - name: Create systemd service file
      copy:
        dest: /etc/systemd/system/{{ service_name }}.service
        content: |
          [Unit]
          Description=Gunicorn instance to serve myflaskapp
          After=network.target

          [Service]
          User={{ user }}
          Group={{ group }}
          WorkingDirectory={{ app_dir }}
          ExecStart={{ venv_dir }}/bin/gunicorn -c {{ app_dir }}{{ gunicorn_config }} app:app

          [Install]
          WantedBy=multi-user.target
        mode: '0644'

    - name: Reload systemd to pick up the new service
      systemd:
        daemon_reload: yes

    - name: Start and enable the Flask app service
      systemd:
        name: "{{ service_name }}"
        state: started
        enabled: yes
```

# Create a application

1. create `touch ./app.py` and paste following in it
```python
from flask import Flask, request, render_template, redirect, url_for
import psycopg2
import threading
import psutil
import os
import boto3
import json
import sys

app = Flask(__name__)

# Function to get the secret from AWS Secrets Manager
def get_secret(secret_id):
    client = boto3.client('secretsmanager', region_name="us-west-2")
    try:
        response = client.get_secret_value(SecretId=secret_id)
        secret_string = response.get('SecretString')
        if not secret_string:
            raise ValueError("SecretString is empty.")
        return json.loads(secret_string)
    except Exception as e:
        print(f"Failed to fetch the secret from AWS Secrets Manager: {e}")
        sys.exit(1)

# Function to get the RDS instance endpoint
def get_rds_endpoint(db_instance_identifier):
    client = boto3.client('rds', region_name="us-west-2")
    try:
        response = client.describe_db_instances(DBInstanceIdentifier=db_instance_identifier)
        endpoint = response['DBInstances'][0]['Endpoint']['Address']
        return endpoint
    except Exception as e:
        print(f"Failed to fetch the RDS instance endpoint: {e}")
        sys.exit(1)

# Fetch the secret and RDS endpoint
def setup_environment():
    secret_id = 'rds-db-sec-023'  # Replace with your secret ID
    db_instance_identifier = 'mydb'  # Replace with your RDS instance ID

    # Fetch the secret
    secret_data = get_secret(secret_id)
    db_user = secret_data.get('username')
    db_pass = secret_data.get('password')
    db_host = get_rds_endpoint(db_instance_identifier)

    if not db_user or not db_pass:
        print("Failed to extract username or password from the secret.")
        sys.exit(1)

    # Set environment variables
    os.environ['DB_USER'] = db_user
    os.environ['DB_PASS'] = db_pass
    os.environ['DB_HOST'] = db_host

# Fetch secrets and RDS endpoint and set environment variables
setup_environment()

# Database connection details
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_NAME = "postgres" 
DB_PASS = os.getenv("DB_PASS") 

DB_PORT = 5432

# Function to connect to the database
def get_db_connection():
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )
    return conn

# Function to create the submissions table if it doesn't exist
def create_table():
    conn = get_db_connection()
    with conn:
        with conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS submissions (
                    id SERIAL PRIMARY KEY,
                    data TEXT NOT NULL
                )
            ''')

# Route to display the form
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        data = request.form['data']
        # Save data to the database
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute('INSERT INTO submissions (data) VALUES (%s)', (data,))
        return redirect(url_for('index'))

    return render_template('index.html')

# Route to display all submissions
@app.route('/submissions')
def submissions():
    conn = get_db_connection()
    with conn:
        with conn.cursor() as cur:
            cur.execute('SELECT * FROM submissions')
            rows = cur.fetchall()
    return render_template('submissions.html', submissions=rows)

# Function to simulate multiple users
def simulate_users(num_users):
    for i in range(num_users):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute('INSERT INTO submissions (data) VALUES (%s)', (f'Simulated User {i + 1}',))

# Route to simulate multiple users
@app.route('/simulate/<int:num_users>')
def simulate(num_users):
    thread = threading.Thread(target=simulate_users, args=(num_users,))
    thread.start()
    return f'Simulating {num_users} users...'

# Route to get CPU and memory usage
@app.route('/usage')
def get_usage():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_percent = psutil.virtual_memory().percent
    return {'cpu': cpu_percent, 'memory': memory_percent}

if __name__ == '__main__':
    create_table()
    app.run(debug=True, host="0.0.0.0")

```

2. create `touch ./gunicorn.py` paste the following
```python
bind = "0.0.0.0:5000"
workers = 2
```

3. create `touch ./requirements.txt` paste the following
```bash
blinker==1.8.2
click==8.1.7
Flask==3.0.3
itsdangerous==2.2.0
Jinja2==3.1.4
MarkupSafe==2.1.5
psutil==6.0.0
psycopg2-binary==2.9.9
Werkzeug==3.0.3
boto3
gunicorn


```
4. Create a templates
 - `touch ./templates/index.html` and paste the following
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Stress Test</title>
    <script>
        function fetchUsage() {
            fetch('/usage')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('cpu-usage').innerText = `CPU Usage: ${data.cpu}%`;
                    document.getElementById('memory-usage').innerText = `Memory Usage: ${data.memory}%`;
                })
                .catch(error => console.error('Error fetching usage data:', error));
        }

        // Fetch usage data every 2 seconds
        setInterval(fetchUsage, 2000);
    </script>
</head>
<body>
    <h1>Stress Test Form</h1>
    <form action="/" method="POST">
        <input type="text" name="data" placeholder="Enter some data" required>
        <button type="submit">Submit</button>
    </form>
    <h2>Submissions</h2>
    <a href="/submissions">View All Submissions</a>
    
    <h2>Simulate Users</h2>
    <form action="/simulate/10" method="GET">
        <button type="submit">Simulate 10 Users</button>
    </form>

    <h2>System Usage</h2>
    <div id="usage">
        <p id="cpu-usage">CPU Usage: 0%</p>
        <p id="memory-usage">Memory Usage: 0%</p>
    </div>
</body>
</html>
```
 - `touch ./templates/submissions.html` paste the following in it
 ```html
 <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Submissions</title>
</head>
<body>
    <h1>All Submissions</h1>
    <ul>
        {% for submission in submissions %}
            <li>{{ submission[1] }}</li>
        {% endfor %}
    </ul>
    <a href="/">Back to Form</a>
</body>
</html>
 ```
# Setup CI-CD Structure 

1. Sigin in AWS Console navigate to IAM console
2. On IAM console click on **Identity providers** 
3. Click on **Add providers**
4. On **Provider type** select **Open ID Connect**
5. On **Provider URL** add `token.actions.githubusercontent.com`
6. On **Audience** add `sts.amazonaws.com`
7. Click on **Add Provider**
8. Click on the provider that you have copy and note down the **ARN** the we just created then click on **Assign Role**
9. Select **Create a New Role** then click **Next**.
10. In **Trusted entity type** select **Web Identity**
11. Scroll down on **Web identity** on **Audience** select `sts.amazonaws.com`
12. On **GitHub organization**  give your github username
13. Leave all to default click on **Next**
14. Select appropriate permission if required for now let's give `AdministratorAccess` permission select **AdministratorAccess** scroll down and click **Next**.
15. On **Role name** give it name as `github-action-role`
16. On **Description** give a description like 
```text
Github Actions role to give terrafrom to setup infrastructure for the application
```
17. Now scroll down and click **Create Role**
18. Now navigate to role that we just created copy and down  the **ARN** of that role.
19. Now go to the github  navigate to your project repository click on **Settings** 
20. Scroll down Under *Security* section click **Secret and Variables** then click on **Action**.
21. Then click on **New Repository Secret** 
22. Give it a name **IAMROLE_GITHUB** and paste the role  arn that you have copied in step 18 then click **Add Secret**.
23. We also create ssh key  run the following to create a ssh key
```bash
ssh-keygen -t rsa -b 4096 -f id_rsa -N ""
```
24. Again click on **New Repository Secret** give it a name as `MYKEY_PUB` and copy the content of `id_rsa.pub` by `cat ./id_rsa.pub` and then click **Add Secret**.
24. create the github actions file for to deploy ci  `touch ./.github/workflows/build.yaml` and paste the following and replace with the `ARN` of the role that you copied in step 18 this will checkout the repo and do aws configure.

```yaml

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with: 
        aws-region: us-west-2
        role-to-assume: ${{ secrets.IAMROLE_GITHUB }}
        role-session-name: BuildSession
```

3. To Install necessary packages  paste the following in `./.github/workflows/build.yaml`

```yaml

    - name: Install unzip, AWS CLI, Ansible, and Terraform
      run: |
        sudo apt-get update
        sudo apt-get install -y unzip awscli gnupg software-properties-common
        wget -O- https://apt.releases.hashicorp.com/gpg | \
          gpg --dearmor | \
          sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg > /dev/null
        echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
          https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
          sudo tee /etc/apt/sources.list.d/hashicorp.list
        sudo apt-get update
        sudo apt-get install terraform -y
        pip install ansible

```
4. To create a server ami maker we create an instance and configure with it with ansible to do that paste the following in `./.github/workflows/build.yaml`
```yaml

    - name: Generate SSH Key Pair and Launch EC2 instances
      run: |
        echo "[cpu-api]" > inventory
        ssh-keygen -t rsa -b 4096 -f id_rsa -N ""
        terraform init
        terraform apply --auto-approve 
      working-directory: tempec2
      continue-on-error: true
    
    - name: Ansible Playbook
      run: |
        sleep 30
        chmod 400 id_rsa
        ansible-playbook -i inventory --private-key id_rsa install-app.yml
      working-directory: tempec2
      continue-on-error: true
```

5. TO Create a AMI and Wait until ami creation is finished paste the following in `./.github/workflows/build.yaml`
```yaml

    - name: Retrieve Instance ID
      id: get_instance_id
      run: |
        INSTANCE_ID=$(aws ec2 describe-instances \
          --filters "Name=tag:Name,Values=amimaker" \
          --query "Reservations[*].Instances[*].InstanceId" \
          --output text)
        echo "INSTANCE_ID=$INSTANCE_ID" >> $GITHUB_ENV
      continue-on-error: true

    - name: Create AMI
      id: create_ami
      run: |
        OUTPUT=$(aws ec2 create-image \
          --instance-id ${{ env.INSTANCE_ID }} \
          --name "MyNewAMI-${{ github.run_number }}" \
          --no-reboot)
        AMI_ID=$(echo $OUTPUT | jq -r '.ImageId')
        echo "AMI_ID=$AMI_ID" >> $GITHUB_ENV
      continue-on-error: true
      
    - name: Wait for AMI to be available
      id: wait_for_ami
      run: |
        AMI_ID=${{ env.AMI_ID }}
        echo "Waiting for AMI $AMI_ID to be available..."
        STATUS="pending"
        while [ "$STATUS" != "available" ]; do
          STATUS=$(aws ec2 describe-images \
            --image-ids $AMI_ID \
            --query "Images[0].State" \
            --output text)
          echo "Current status: $STATUS"
          if [ "$STATUS" == "available" ]; then
            echo "AMI $AMI_ID is available."
            break
          fi
          sleep 30  # Wait for 30 seconds before checking again
        done
      continue-on-error: true
```

6. To grab ami id the we have just created and destroy the ami maker ec2 paste the following in the `./.github/workflows/build.yaml`
```yaml
    - name: Output AMI ID
      run: echo "AMI ID is ${{ env.AMI_ID }}"
      continue-on-error: true

    - name: Terraform destroy
      run: |
        terraform destroy --auto-approve
      working-directory: tempec2
      continue-on-error: true
```
7. To setup our infra paste the following and handle a failure to destroy paste the following in  `./.github/workflows/build.yaml`
```yaml
    - name: Terraform Update the infrastructure
      run: |
        echo "$MY_PUB_KEY" > mykey.pub
        terraform init
        terraform apply -var="ami-id=${{ env.AMI_ID }}" --auto-approve
      working-directory: terraform
      continue-on-error: true
      env:
          MY_PUB_KEY: ${{ secrets.MYKEY_PUB }}


    - name: Terraform Destroy on Failure
      if: failure()
      run: terraform destroy --auto-approve
      working-directory: terraform
```

Now run the following commands to push to your github repository
```bash
git add .
git commit -m "Updated the repos"
git push
```
Check the github actions and your infrastructre
