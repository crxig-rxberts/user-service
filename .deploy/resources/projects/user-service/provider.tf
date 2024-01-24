provider "aws" {
  region = "eu-west-1"
}

provider "nomad" {
  address = "http://${element(data.aws_instances.nomad_server.public_ips, 0)}:4646"
}

terraform {
  backend "s3" {
  }
}