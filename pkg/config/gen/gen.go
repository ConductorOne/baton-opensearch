package main

import (
	cfg "github.com/conductorone/baton-opensearch/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	config.Generate("opensearch", cfg.Config)
}
