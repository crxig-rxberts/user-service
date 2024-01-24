data "aws_instances" "nomad_server" {
  filter {
    name   = "tag:Name"
    values = ["nomad-server"]
  }
}