terraform {
  backend "s3" {
    bucket         = "crewmeisterbucket"
    key            = "terraform.tfstate"
    region         = "eu-central-1"
  }
}