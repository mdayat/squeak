variable "url" {
  type    = string
  default = ""
}

env "prod" {
  src = "file://schema.sql"
  url = var.url
  dev = "docker://postgres/15/dev?search_path=public"
  migration {
    dir = "file://migrations"
  }
  format {
    migrate {
      diff = format("{{ sql . \"  \" }}")
    }
  }
}