#!/bin/bash

# Fetch the secret from AWS Secrets Manager
SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id rds-credentials1 --query SecretString --output text)

# Check if the secret fetch was successful
if [ $? -ne 0 ]; then
  echo "Failed to fetch the secret from AWS Secrets Manager."
  exit 1
fi

# Extract username and password using jq
DB_USER=$(echo "$SECRET_JSON" | jq -r '.username')
DB_PASS=$(echo "$SECRET_JSON" | jq -r '.password')

# Check if jq commands were successful
if [ -z "$DB_USER" ] || [ -z "$DB_PASS" ]; then
  echo "Failed to extract username or password from the secret."
  exit 1
fi

# Fetch the RDS instance endpoint (hostname)
DB_INSTANCE_IDENTIFIER="mydb"  # Replace with your RDS instance ID
DB_HOST=$(aws rds describe-db-instances --db-instance-identifier "$DB_INSTANCE_IDENTIFIER" --query "DBInstances[0].Endpoint.Address" --output text)

# Check if the RDS endpoint fetch was successful
if [ $? -ne 0 ]; then
  echo "Failed to fetch the RDS instance endpoint."
  exit 1
fi

# Export environment variables
export DB_USER
export DB_PASS
export DB_HOST

# Print the environment variables (optional)
echo "DB_USER=$DB_USER"
echo "DB_PASS=$DB_PASS"
echo "DB_HOST=$DB_HOST"
