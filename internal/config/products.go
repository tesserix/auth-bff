package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ProductsFile is the top-level structure of products.yaml.
type ProductsFile struct {
	PlatformDomain string          `yaml:"platformDomain"`
	Products       []ProductConfig `yaml:"products"`
}

// ProductConfig defines a product (e.g. tesserix, marketplace).
type ProductConfig struct {
	Name   string      `yaml:"name"`
	Domain string      `yaml:"domain"`
	Apps   []AppConfig `yaml:"apps"`
}

// LoadProducts reads products.yaml from the configured path,
// resolves client secrets from environment variables, and
// populates cfg.Apps and cfg.PlatformDomain.
func (c *Config) LoadProducts() error {
	path := c.ProductsConfigPath
	if path == "" {
		path = "products.yaml"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read products config %s: %w", path, err)
	}

	var pf ProductsFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("parse products config: %w", err)
	}

	if pf.PlatformDomain == "" {
		return fmt.Errorf("products config: platformDomain is required")
	}
	c.PlatformDomain = pf.PlatformDomain

	var apps []AppConfig
	for _, product := range pf.Products {
		if product.Domain == "" {
			return fmt.Errorf("products config: product %q has no domain", product.Name)
		}
		for _, app := range product.Apps {
			if app.ClientSecretEnv == "" {
				return fmt.Errorf("products config: app %q in product %q has no clientSecretEnv", app.Name, product.Name)
			}
			app.OAuthClientSecret = os.Getenv(app.ClientSecretEnv)
			app.ProductDomain = product.Domain
			apps = append(apps, app)
		}
	}

	if len(apps) == 0 {
		return fmt.Errorf("products config: no apps defined")
	}

	c.Apps = apps
	return nil
}
