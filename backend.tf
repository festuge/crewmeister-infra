terraform {
  backend "s3" {
    bucket         = "crewmeisterbucket"
    key            = "infra-state/terraform.tfstate"
    region         = "eu-central-1"
  }
}