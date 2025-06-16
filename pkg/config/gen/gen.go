package main

import (
	"github.com/conductorone/baton-sdk/pkg/config"
	cfg "github.com/conductorone/baton-opensearch/pkg/config"
)

func main() {
	config.Generate("opensearch", cfg.Config)
}
