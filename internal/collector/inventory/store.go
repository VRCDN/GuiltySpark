// Package inventory wraps the storage layer for inventory operations.
package inventory

import (
	"context"

	"github.com/VRCDN/guiltyspark/internal/collector/storage"
	"github.com/VRCDN/guiltyspark/internal/common/models"
)

// Store is a thin wrapper so callers don't have to import the storage interface directly.
type Store struct {
	storage storage.Storage
}

// New creates an inventory Store.
func New(s storage.Storage) *Store {
	return &Store{storage: s}
}

// Save persists a system inventory snapshot.
func (s *Store) Save(ctx context.Context, inv *models.SystemInventory) error {
	return s.storage.SaveInventory(ctx, inv)
}

// Get retrieves the latest inventory for the given agent.
func (s *Store) Get(ctx context.Context, agentID string) (*models.SystemInventory, error) {
	return s.storage.GetInventory(ctx, agentID)
}

// List returns all agent inventories.
func (s *Store) List(ctx context.Context) ([]*models.SystemInventory, error) {
	return s.storage.ListInventory(ctx)
}
